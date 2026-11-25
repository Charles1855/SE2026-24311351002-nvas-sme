import queue
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import ttk, messagebox, scrolledtext

from analysis import vuln_matcher
from analysis.scan_integration import record_scan
from analysis.vuln_matcher import match_scan_results
from auth.service import AuthError
from database.db import init_db, save_scan_result
from gui import theme
from scanner.port_scanner import PortScanner
from scanner.scope_guard import ScopeError

STEPS = [
    ("scan", "Port scan"),
    ("match", "CVE lookup"),
    ("save", "Save results"),
]

# symbol and colour for each step state
STEP_STYLE = {
    "waiting": ("\u25cb", theme.MUTED),   # hollow circle
    "active": ("\u25cf", theme.ACCENT),   # filled circle
    "done": ("\u2714", theme.GOOD),       # tick
    "failed": ("\u2716", theme.BAD),      # cross
}

LOG_COLORS = {"info": theme.TEXT, "ok": theme.GOOD, "warn": theme.WARN, "error": theme.BAD}


class ScanView(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=theme.BG, padx=32, pady=16)
        self.app = app
        self.messages = queue.Queue()  # worker thread -> GUI thread
        self.scanning = False
        self.target = ""
        self.matched = []
        self.started_at = 0.0
        self.elapsed = 0

        tk.Label(
            self, text="New Scan", bg=theme.BG, fg=theme.TEXT,
            font=(theme.FONT, 20, "bold"),
        ).pack(anchor="w")
        tk.Label(
            self, text="Enter the IP address of a device inside your signed scope.",
            bg=theme.BG, fg=theme.MUTED, font=(theme.FONT, 10),
        ).pack(anchor="w", pady=(0, 10))

        # ---- input card ----
        input_card = self.make_card()
        input_card.pack(fill="x")
        row = tk.Frame(input_card, bg=theme.CARD)
        row.pack(fill="x", padx=18, pady=12)

        tk.Label(
            row, text="Target IP", bg=theme.CARD, fg=theme.TEXT,
            font=(theme.FONT, 10, "bold"),
        ).pack(side="left")
        self.target_entry = ttk.Entry(row, width=20, font=(theme.FONT, 12))
        self.target_entry.pack(side="left", padx=12)
        self.target_entry.insert(0, app.last_target)
        self.target_entry.bind("<Return>", lambda event: self.start_scan())
        self.target_entry.focus_set()

        self.scan_button = ttk.Button(
            row, text="Start Scan", style="Accent.TButton", command=self.start_scan
        )
        self.scan_button.pack(side="left")
        self.results_button = ttk.Button(
            row, text="View Results", command=self.open_results, state="disabled"
        )
        self.results_button.pack(side="left", padx=10)

        self.elapsed_label = tk.Label(
            row, text="", bg=theme.CARD, fg=theme.MUTED, font=(theme.FONT, 10)
        )
        self.elapsed_label.pack(side="right")

        # ---- progress card ----
        progress_card = self.make_card()
        progress_card.pack(fill="x", pady=(10, 0))
        inner = tk.Frame(progress_card, bg=theme.CARD)
        inner.pack(fill="x", padx=18, pady=10)

        steps_row = tk.Frame(inner, bg=theme.CARD)
        steps_row.pack(fill="x", pady=(0, 8))
        self.step_labels = {}
        for number, (key, text) in enumerate(STEPS, start=1):
            label = tk.Label(steps_row, bg=theme.CARD, font=(theme.FONT, 10, "bold"))
            label.pack(side="left", padx=(0, 28))
            self.step_labels[key] = (label, f"{number}  {text}")
        self.reset_steps()

        self.progress = ttk.Progressbar(inner, mode="determinate")
        self.progress.pack(fill="x")
        self.status = tk.Label(
            inner, text="Ready.", anchor="w", bg=theme.CARD, fg=theme.TEXT,
            font=(theme.FONT, 10),
        )
        self.status.pack(fill="x", pady=(8, 0))

        # ---- activity log ----
        tk.Label(
            self, text="Activity log", bg=theme.BG, fg=theme.TEXT,
            font=(theme.FONT, 10, "bold"),
        ).pack(anchor="w", pady=(10, 4))
        log_card = self.make_card()
        log_card.pack(fill="both", expand=True)
        self.log_box = scrolledtext.ScrolledText(
            log_card, height=6, state="disabled", font=(theme.MONO, 10),
            bg=theme.CARD, relief="flat", padx=10, pady=8, borderwidth=0,
        )
        self.log_box.pack(fill="both", expand=True)
        self.log_box.tag_configure("time", foreground=theme.MUTED)
        self.apply_role()
        for level, color in LOG_COLORS.items():
            self.log_box.tag_configure(level, foreground=color)

    # ---------- small helpers ----------

    def apply_role(self):
        """Roles that cannot scan see why, instead of a button that does nothing."""
        if self.app.can("scan"):
            return
        self.scan_button.config(state="disabled")
        self.target_entry.config(state="disabled")
        self.status.config(text=f"Your role ({self.app.session.role}) can look at results "
                                "but cannot start scans.")

    def make_card(self):
        return tk.Frame(
            self, bg=theme.CARD, highlightbackground=theme.BORDER,
            highlightcolor=theme.BORDER, highlightthickness=1,
        )

    def set_step(self, key, state):
        label, text = self.step_labels[key]
        symbol, color = STEP_STYLE[state]
        label.config(text=f"{symbol} {text}", fg=color)

    def reset_steps(self):
        for key, _ in STEPS:
            self.set_step(key, "waiting")

    def log(self, text, level="info"):
        stamp = datetime.now().strftime("%H:%M:%S")
        self.log_box.config(state="normal")
        self.log_box.insert("end", f"[{stamp}] ", "time")
        self.log_box.insert("end", text + "\n", level)
        self.log_box.see("end")
        self.log_box.config(state="disabled")

    def set_controls(self, enabled):
        state = "normal" if enabled else "disabled"
        self.scan_button.config(state=state)
        self.target_entry.config(state=state)

    def stop_progress(self, value):
        self.progress.stop()
        self.progress.config(mode="determinate", maximum=100, value=value)

    # ---------- starting a scan (GUI thread) ----------

    def target_allowed(self, text):
        """
        Ask the scope guard first. If it says no, nothing is started and nothing
        is sent. Returns the checked target, or None when it was refused.
        """
        guard = self.app.guard
        if guard is None:
            self.show_refusal("Scope not loaded", self.app.scope_problem)
            return None
        try:
            validated = guard.authorise(text, actor=self.app.session.username)
        except ScopeError as error:
            self.show_refusal("Target refused", str(error))
            return None
        if not validated.is_single_host:
            self.show_refusal("One IP address needed",
                              "Scanning a whole network is not available yet. "
                              "Enter a single IP address.")
            return None
        return validated

    def show_refusal(self, title, message):
        self.status.config(text="Refused. Nothing was scanned.")
        self.log(f"REFUSED: {message}", "error")
        messagebox.showerror(title, message)

    def start_scan(self):
        if self.scanning:
            return
        try:
            self.app.require("scan")
        except AuthError as error:
            self.show_refusal("Not allowed", error.message)
            return
        validated = self.target_allowed(self.target_entry.get())
        if validated is None:
            return

        self.target = str(validated)
        self.app.last_target = self.target
        self.scanning = True
        self.started_at = time.time()
        self.set_controls(False)
        self.results_button.config(state="disabled", style="TButton")
        self.scan_button.config(text="Scanning...", style="Accent.TButton")
        self.reset_steps()
        self.stop_progress(0)

        self.log_box.config(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.config(state="disabled")

        threading.Thread(target=self.run_scan, args=(validated,), daemon=True).start()
        self.after(100, self.poll_messages)
        self.after(500, self.tick)

    def tick(self):
        if not self.scanning:
            return
        seconds = int(time.time() - self.started_at)
        self.elapsed_label.config(text=f"Elapsed {seconds // 60:02d}:{seconds % 60:02d}")
        self.after(500, self.tick)

    # ---------- the actual work (background thread) ----------
    # The worker never touches widgets. It only puts messages in the queue.

    def run_scan(self, validated):
        target = str(validated)
        put = self.messages.put
        # NVD problems (timeouts, retries) show up in the activity log too
        vuln_matcher.warning_hook = lambda text: put(("log", text.strip(), "warn"))
        try:
            init_db()

            put(("step", "scan", "active"))
            put(("indeterminate",))
            put(("status", f"Scanning {target} (ports 1-10000). This can take a minute..."))
            put(("log", f"Starting port scan on {target}", "info"))
            scan_results = PortScanner(self.app.guard).scan_target(validated)

            if not scan_results:
                put(("step", "scan", "failed"))
                put(("empty", target))
                return
            put(("log", f"Port scan finished: {len(scan_results)} open port(s) found", "ok"))
            put(("step", "scan", "done"))

            put(("step", "match", "active"))

            def on_progress(done, total, label):
                put(("progress", done, total, label))

            matched = match_scan_results(scan_results, progress_callback=on_progress)
            put(("log", "CVE lookup finished", "ok"))
            put(("step", "match", "done"))

            put(("step", "save", "active"))
            put(("status", "Saving results to the database..."))
            for entry in matched:
                save_scan_result(
                    target=target,
                    port=entry["port"],
                    service=entry["service"],
                    product=entry["product"],
                    version=entry["version"],
                    cves=entry["cves"],
                )
            put(("log", "Results saved to the database", "ok"))
            self.record_findings(target, matched, put)
            put(("step", "save", "done"))

            put(("done", target, matched))
        except Exception as error:
            put(("error", str(error)))

    def record_findings(self, target, matched, put):
        """
        Rank the findings, store them, and compare with the previous scan of this
        target. Runs on the worker thread, so it only reports through `put`.
        """
        if vuln_matcher.lookup_failures:
            put(("log", f"{vuln_matcher.lookup_failures} NVD lookup(s) failed, so this scan was "
                        "not recorded for comparison (missing CVEs would wrongly show as "
                        "'fixed'). Scan again when the connection is stable.", "warn"))
            return
        try:
            recorded = record_scan(matched, target)
        except Exception as error:  # the scan already succeeded: never lose it over this
            put(("log", f"Could not rank or compare findings: {error}", "warn"))
            return
        findings = recorded["findings"]
        put(("log", f"Ranked {len(findings)} finding(s) by CVSS and asset criticality", "ok"))
        fallback = sum(1 for f in findings if f.score_basis != "CVSS v3.1")
        if fallback:
            put(("log", f"{fallback} finding(s) use a CVSS fallback score (not v3.1)", "warn"))

        delta = recorded["delta"]
        if delta is None:
            put(("log", "First recorded scan of this target: nothing to compare yet", "info"))
            return
        s = delta["summary"]
        put(("log", f"Compared with scan #{recorded['previous_run_id']}: {s['new']} new, "
                    f"{s['fixed']} fixed, {s['persisting']} persisting", "ok"))
        if recorded["report_paths"]:
            put(("log", f"Delta report saved: {recorded['report_paths'][1]}", "ok"))

    # ---------- receiving updates (GUI thread) ----------

    def poll_messages(self):
        try:
            while True:
                self.handle_message(self.messages.get_nowait())
        except queue.Empty:
            pass
        if self.scanning:
            self.after(100, self.poll_messages)

    def handle_message(self, msg):
        kind = msg[0]
        if kind == "log":
            level = msg[2] if len(msg) > 2 else "info"
            self.log(msg[1], level)
        elif kind == "status":
            self.status.config(text=msg[1])
        elif kind == "step":
            self.set_step(msg[1], msg[2])
        elif kind == "indeterminate":
            self.progress.config(mode="indeterminate")
            self.progress.start(12)
        elif kind == "progress":
            _, done, total, label = msg
            self.progress.stop()
            self.progress.config(mode="determinate", maximum=total, value=done)
            self.status.config(text=f"{label} ({done}/{total})")
            self.log(label)
        elif kind == "done":
            self.finish_scan(msg[1], msg[2])
        elif kind == "empty":
            self.no_ports_found(msg[1])
        elif kind == "error":
            self.fail_scan(msg[1])

    def end_scan(self):
        self.scanning = False
        self.elapsed = int(time.time() - self.started_at)
        self.set_controls(True)
        self.scan_button.config(text="Scan Again", style="TButton")

    def finish_scan(self, target, matched):
        self.end_scan()
        self.matched = matched
        self.stop_progress(100)

        with_cves = sum(1 for entry in matched if entry["cves"])
        self.status.config(
            text=f"Scan complete: {len(matched)} open ports, "
                 f"{with_cves} with known vulnerabilities."
        )
        self.elapsed_label.config(text=f"Finished in {self.elapsed}s")
        self.log("Scan complete. Click 'View Results' to see the findings.", "ok")
        self.results_button.config(state="normal", style="Accent.TButton")

    def no_ports_found(self, target):
        self.end_scan()
        self.stop_progress(0)
        self.status.config(text="No open ports found.")
        self.log(
            f"No open ports were found on {target}. The host may be down or a firewall "
            "may be blocking the scan. Check that the target is running and the IP is correct.",
            "warn",
        )

    def fail_scan(self, error):
        self.end_scan()
        self.stop_progress(0)
        self.status.config(text="Scan failed.")
        self.log(f"ERROR: {error}", "error")
        messagebox.showerror("Scan failed", f"The scan could not finish:\n\n{error}")

    def open_results(self):
        info = {"seconds": self.elapsed, "finished": datetime.now(),
                "operator": self.app.session.username}
        self.app.show_results_view(self.target, self.matched, info)