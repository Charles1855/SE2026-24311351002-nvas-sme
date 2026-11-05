import ipaddress
import queue
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import ttk, messagebox, scrolledtext

from analysis import vuln_matcher
from analysis.vuln_matcher import match_scan_results
from database.db import init_db, save_scan_result
from gui import theme
from scanner.port_scanner import PortScanner

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
            self, text="Enter the IP address of the device you want to check.",
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
        for level, color in LOG_COLORS.items():
            self.log_box.tag_configure(level, foreground=color)

    # ---------- small helpers ----------

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

    def start_scan(self):
        if self.scanning:
            return
        target = self.target_entry.get().strip()
        try:
            ipaddress.ip_address(target)
        except ValueError:
            messagebox.showerror(
                "Invalid IP address",
                "Please enter a valid IP address, for example 192.168.0.1",
            )
            return

        self.app.last_target = target
        self.target = target
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

        threading.Thread(target=self.run_scan, args=(target,), daemon=True).start()
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

    def run_scan(self, target):
        put = self.messages.put
        # NVD problems (timeouts, retries) show up in the activity log too
        vuln_matcher.warning_hook = lambda text: put(("log", text.strip(), "warn"))
        try:
            init_db()

            put(("step", "scan", "active"))
            put(("indeterminate",))
            put(("status", f"Scanning {target} (ports 1-10000). This can take a minute..."))
            put(("log", f"Starting port scan on {target}", "info"))
            scan_results = PortScanner().scan_target(target)

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
            put(("step", "save", "done"))

            put(("done", target, matched))
        except Exception as error:
            put(("error", str(error)))

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
        info = {"seconds": self.elapsed, "finished": datetime.now()}
        self.app.show_results_view(self.target, self.matched, info)