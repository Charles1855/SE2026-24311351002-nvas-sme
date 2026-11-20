import tkinter as tk

from analysis.vuln_matcher import HAS_KEY
from gui import theme
from gui.results_view import ResultsView
from gui.scan_view import ScanView
from scanner.scope_guard import ScopeError, load_default_guard


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Vulnerability Assessment System")
        theme.setup_styles(self)
        theme.center_window(self, 1040, 760)
        self.minsize(900, 540)

        # remembered so "New Scan" comes back with the last target filled in
        self.last_target = "192.168.56.101"

        # The signed scope decides what may be scanned. Without it, nothing is.
        try:
            self.guard = load_default_guard()
            self.scope_problem = ""
        except ScopeError as error:
            self.guard = None
            self.scope_problem = f"{error} ({error.code})"

        # Header bar (stays visible on every screen)
        header = tk.Frame(self, bg=theme.NAVY)
        header.pack(fill="x")
        tk.Label(
            header,
            text="Network Vulnerability Assessment System",
            bg=theme.NAVY,
            fg="white",
            font=(theme.FONT, 15, "bold"),
        ).pack(side="left", padx=(28, 0), pady=14)
        tk.Label(
            header,
            text="Scan a device, match its services to known CVEs and rank the risk",
            bg=theme.NAVY,
            fg="#b8c7dc",
            font=(theme.FONT, 10),
        ).pack(side="right", padx=28)

        # Footer bar (packed before the content so it always keeps its space)
        footer = tk.Frame(self, bg="#e6ebf1")
        footer.pack(side="bottom", fill="x")
        if HAS_KEY:
            key_text, key_color = "NVD API key: loaded", theme.GOOD
        else:
            key_text, key_color = "NVD API key: missing (lookups will be slow)", theme.WARN
        tk.Label(
            footer, text=key_text, bg="#e6ebf1", fg=key_color,
            font=(theme.FONT, 9, "bold"),
        ).pack(side="left", padx=28, pady=6)
        if self.guard:
            scope_text, scope_color = f"Scope: {self.guard.describe()}", theme.GOOD
        else:
            scope_text, scope_color = "Scope NOT LOADED: scans are blocked", theme.BAD
        tk.Label(
            footer, text=scope_text, bg="#e6ebf1", fg=scope_color,
            font=(theme.FONT, 9, "bold"),
        ).pack(side="right", padx=28)

        # Area where the screens (frames) are swapped in and out
        self.container = tk.Frame(self, bg=theme.BG)
        self.container.pack(fill="both", expand=True)

        self.current_frame = None
        self.show_scan_view()

    def switch_frame(self, frame_class, **kwargs):
        if self.current_frame is not None:
            self.current_frame.destroy()
        self.current_frame = frame_class(self.container, self, **kwargs)
        self.current_frame.pack(fill="both", expand=True)

    def show_scan_view(self):
        self.switch_frame(ScanView)

    def show_results_view(self, target, matched, info=None):
        self.switch_frame(ResultsView, target=target, matched=matched, info=info)