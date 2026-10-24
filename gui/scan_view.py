import ipaddress
import queue
import threading
import tkinter as tk
from datetime import datetime
from tkinter import ttk, messagebox, scrolledtext

from scanner.port_scanner import PortScanner
from analysis.vuln_matcher import match_scan_results
from database.db import init_db, save_scan_result

STEPS = [
    ("scan", "1. Port scan"),
    ("match", "2. CVE lookup"),
    ("save", "3. Save results"),
]

# symbol and colour for each step state
STEP_STYLE = {
    "waiting": ("\u25cb ", "#888888"),  # hollow circle
    "active": ("\u25cf ", "#1565c0"),   # filled circle
    "done": ("\u2714 ", "#2e7d32"),     # tick
}


class ScanView(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padx=30, pady=20)
        self.app = app
        self.messages = queue.Queue()  # worker thread -> GUI thread
        self.scanning = False
        self.target = ""
        self.matched = []

        tk.Label(self, text="New Scan", font=("Segoe UI", 18, "bold")).pack(anchor="w")
        tk.Label(
            self,
            text="Enter the IP address of the device you want to check.",
            fg="#555555",
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(0, 15))

        # Input row
        row = tk.Frame(self)
        row.pack(fill="x")
        tk.Label(row, text="Target IP:", font=("Segoe UI", 10)).pack(side="left")
        self.target_entry = ttk.Entry(row, width=22, font=("Segoe UI", 11))
        self.target_entry.pack(side="left", padx=10)
        self.target_entry.insert(0, "192.168.56.101")

        self.scan_button = ttk.Button(row, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(side="left")
        self.results_button = ttk.Button(
            row, text="View Results", command=self.open_results, state="disabled"
        )
        self.results_button.pack(side="left", padx=10)

        tk.Label(
            self,
            text="Only scan systems you own or have permission to test.",
            fg="#b71c1c",
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(6, 15))

        # Step indicators
        steps_frame = tk.Frame(self)
        steps_frame.pack(fill="x", pady=(0, 10))
        self.step_labels = {}
        for key, text in STEPS:
            label = tk.Label(steps_frame, font=("Segoe UI", 10, "bold"))
            label.pack(side="left", padx=(0, 25))
            self.step_labels[key] = (label, text)
        self.reset_steps()

        # Progress bar and status line
        self.progress = ttk.Progressbar(self, mode="determinate")
        self.progress.pack(fill="x")
        self.status = tk.Label(self, text="Ready.", anchor="w", font=("Segoe UI", 10))
        self.status.pack(fill="x", pady=(6, 10))

        # Live activity log
        tk.Label(self, text="Activity log", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.log_box = scrolledtext.ScrolledText(
            self, height=14, state="disabled", font=("Consolas", 10), bg="#fafafa"
        )
        self.log_box.pack(fill="both", expand=True)

    # ---------- small helpers ----------

    def set_step(self, key, state):
        label, text = self.step_labels[key]
        symbol, color = STEP_STYLE[state]
        label.config(text=symbol + text, fg=color)

    def reset_steps(self):
        for key, _ in STEPS:
            self.set_step(key, "waiting")

    def log(self, text):
        stamp = datetime.now().strftime("%H:%M:%S")
        self.log_box.config(state="normal")
        self.log_box.insert("end", f"[{stamp}] {text}\n")
        self.log_box.see("end")
        self.log_box.config(state="disabled")

    def set_controls(self, enabled):
        state = "normal" if enabled else "disabled"
        self.scan_button.config(state=state)
        self.target_entry.config(state=state)

    # ---------- starting a scan (GUI thread) ----------

    def start_scan(self):
        target = self.target_entry.get().strip()
        try:
            ipaddress.ip_address(target)
        except ValueError:
            messagebox.showerror(
                "Invalid IP address",
                "Please enter a valid IP address, for example 192.168.56.101.",
            )
            return

        self.target = target
        self.scanning = True
        self.set_controls(False)
        self.results_button.config(state="disabled")
        self.reset_steps()

        self.log_box.config(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.config(state="disabled")

        threading.Thread(target=self.run_scan, args=(target,), daemon=True).start()
        self.after(100, self.poll_messages)

    # ---------- the actual work (background thread) ----------
    # The worker never touches widgets. It only puts messages in the queue.

    def run_scan(self, target):
        put = self.messages.put
        try:
            init_db()

            put(("step", "scan", "active"))
            put(("indeterminate",))
            put(("status", f"Scanning {target} (ports 1-10000). This can take a minute..."))
            put(("log", f"Starting port scan on {target}"))
            scan_results = PortScanner().scan_target(target)
            put(("log", f"Port scan finished: {len(scan_results)} open port(s) found"))
            put(("step", "scan", "done"))

            put(("step", "match", "active"))

            def on_progress(done, total, label):
                put(("progress", done, total, label))

            matched = match_scan_results(scan_results, progress_callback=on_progress)
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
            put(("log", "Results saved to the database"))
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
            self.log(msg[1])
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
        elif kind == "error":
            self.fail_scan(msg[1])

    def finish_scan(self, target, matched):
        self.scanning = False
        self.matched = matched
        self.progress.stop()
        self.progress.config(mode="determinate", maximum=100, value=100)

        with_cves = sum(1 for entry in matched if entry["cves"])
        self.status.config(
            text=f"Scan complete: {len(matched)} open ports, "
                 f"{with_cves} with known vulnerabilities."
        )
        self.log("Scan complete. Click 'View Results' to see the findings.")
        self.set_controls(True)
        self.results_button.config(state="normal")

    def fail_scan(self, error):
        self.scanning = False
        self.progress.stop()
        self.progress.config(mode="determinate", maximum=100, value=0)
        self.status.config(text="Scan failed.")
        self.log(f"ERROR: {error}")
        self.set_controls(True)
        messagebox.showerror("Scan failed", f"The scan could not finish:\n\n{error}")

    def open_results(self):
        self.app.show_results_view(self.target, self.matched)