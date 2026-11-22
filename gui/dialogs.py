import tkinter as tk
from tkinter import ttk

from gui import theme


class FormDialog(tk.Toplevel):
    """A small modal form. FormDialog.ask(...) returns a dict of answers, or None if cancelled."""

    def __init__(self, parent, title, fields, submit_text="OK"):
        super().__init__(parent)
        self.title(title)
        self.configure(bg=theme.CARD, padx=24, pady=20)
        self.resizable(False, False)
        self.transient(parent.winfo_toplevel())
        self.result = None
        self.widgets = {}
        for key, label, kind, options in fields:
            self.add_field(key, label, kind, options)
        self.error = tk.Label(self, text="", fg=theme.BAD, bg=theme.CARD,
                              wraplength=280, justify="left", font=(theme.FONT, 9))
        self.error.pack(anchor="w", pady=(4, 0))
        self.add_buttons(submit_text)
        self.bind("<Return>", lambda event: self.submit())
        self.bind("<Escape>", lambda event: self.destroy())
        self.grab_set()
        next(iter(self.widgets.values())).focus_set()

    def add_field(self, key, label, kind, options):
        tk.Label(self, text=label, bg=theme.CARD, fg=theme.TEXT,
                 font=(theme.FONT, 10, "bold")).pack(anchor="w", pady=(8, 2))
        if kind == "choice":
            widget = ttk.Combobox(self, values=list(options), state="readonly", width=28)
            widget.current(0)
        else:
            widget = ttk.Entry(self, width=30, font=(theme.FONT, 11),
                               show="*" if kind == "password" else "")
        widget.pack(anchor="w")
        self.widgets[key] = widget

    def add_buttons(self, submit_text):
        row = tk.Frame(self, bg=theme.CARD)
        row.pack(fill="x", pady=(14, 0))
        ttk.Button(row, text=submit_text, style="Accent.TButton",
                   command=self.submit).pack(side="right")
        ttk.Button(row, text="Cancel", command=self.destroy).pack(side="right", padx=(0, 8))

    def submit(self):
        self.result = {key: widget.get() for key, widget in self.widgets.items()}
        self.destroy()

    @classmethod
    def ask(cls, parent, title, fields, submit_text="OK"):
        dialog = cls(parent, title, fields, submit_text)
        dialog.wait_window()
        return dialog.result