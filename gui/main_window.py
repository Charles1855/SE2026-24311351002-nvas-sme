import tkinter as tk
from tkinter import ttk

from gui.scan_view import ScanView
from gui.results_view import ResultsView

HEADER_BG = "#1f3a5f"


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Vulnerability Assessment System")
        self.geometry("1000x700")
        self.minsize(900, 620)

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview", rowheight=28, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        style.configure("TButton", font=("Segoe UI", 10), padding=6)

        # Header bar (stays visible on every screen)
        header = tk.Frame(self, bg=HEADER_BG)
        header.pack(fill="x")
        tk.Label(
            header,
            text="Network Vulnerability Assessment System",
            bg=HEADER_BG,
            fg="white",
            font=("Segoe UI", 16, "bold"),
        ).pack(side="left", padx=20, pady=14)

        # Area where the screens (frames) are swapped in and out
        self.container = tk.Frame(self)
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

    def show_results_view(self, target, matched):
        self.switch_frame(ResultsView, target=target, matched=matched)