"""Colours, fonts and ttk styles shared by every screen."""
from tkinter import ttk

FONT = "Segoe UI"
MONO = "Consolas"

NAVY = "#1f3a5f"
BG = "#f4f6f9"
CARD = "#ffffff"
BORDER = "#d9dee5"
TEXT = "#1b2733"
MUTED = "#66727f"
ACCENT = "#1565c0"
ACCENT_DARK = "#0d47a1"
GOOD = "#2e7d32"
WARN = "#e65100"
BAD = "#b71c1c"

RISK_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# (background, text) used by the summary cards and the table rows
RISK_COLORS = {
    "CRITICAL": ("#b71c1c", "#ffffff"),
    "HIGH": ("#e65100", "#ffffff"),
    "MEDIUM": ("#fbc02d", "#1b2733"),
    "LOW": ("#c8e6c9", "#1b2733"),
    "INFO": ("#eceff1", "#1b2733"),
}

# text colour for severity words inside the details panel
SEVERITY_TEXT = {
    "CRITICAL": "#b71c1c",
    "HIGH": "#e65100",
    "MEDIUM": "#9a6b00",
    "LOW": "#2e7d32",
}


def risk_label(level):
    # INFO means "no CVE matched", which is not the same as "safe"
    return "NO MATCH" if level == "INFO" else level


def center_window(window, width, height):
    # never taller or wider than the screen (laptops with display scaling have little room)
    width = min(width, window.winfo_screenwidth() - 40)
    height = min(height, window.winfo_screenheight() - 80)
    x = (window.winfo_screenwidth() - width) // 2
    y = max((window.winfo_screenheight() - height) // 2 - 20, 0)
    window.geometry(f"{width}x{height}+{x}+{y}")


def _fixed_map(style, option):
    # Known ttk quirk: without this, row colours set with tags can be ignored
    return [
        entry for entry in style.map("Treeview", query_opt=option)
        if entry[:2] != ("!disabled", "!selected")
    ]


def setup_styles(root):
    style = ttk.Style(root)
    style.theme_use("clam")
    root.configure(bg=BG)

    style.configure("TButton", font=(FONT, 10), padding=(14, 7))
    style.configure(
        "Accent.TButton",
        font=(FONT, 10, "bold"),
        padding=(18, 8),
        background=ACCENT,
        foreground="white",
        borderwidth=0,
    )
    style.map(
        "Accent.TButton",
        background=[("disabled", "#9bb7d8"), ("active", ACCENT_DARK)],
        foreground=[("disabled", "#eaf0f7")],
    )

    style.configure(
        "Treeview",
        rowheight=28,
        font=(FONT, 10),
        background=CARD,
        fieldbackground=CARD,
        borderwidth=0,
    )
    style.configure(
        "Treeview.Heading",
        font=(FONT, 10, "bold"),
        background="#e6ebf1",
        foreground=TEXT,
        relief="flat",
        padding=(6, 6),
    )
    style.map(
        "Treeview",
        foreground=[("selected", "white")] + _fixed_map(style, "foreground"),
        background=[("selected", NAVY)] + _fixed_map(style, "background"),
    )
    style.map("Treeview.Heading", background=[("active", "#d8dfe8")])

    style.configure(
        "Horizontal.TProgressbar",
        troughcolor="#e1e6ec",
        background=ACCENT,
        borderwidth=0,
        thickness=14,
    )