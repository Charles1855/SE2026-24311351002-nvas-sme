import tkinter as tk
from tkinter import ttk

from auth.service import AuthError
from gui import theme


class LoginView(tk.Frame):
    """Sign-in screen. On a brand new installation it asks for the administrator account instead."""

    def __init__(self, parent, app):
        super().__init__(parent, bg=theme.BG)
        self.app = app
        self.setup_mode = app.auth.needs_setup()
        card = tk.Frame(self, bg=theme.CARD, highlightbackground=theme.BORDER,
                        highlightcolor=theme.BORDER, highlightthickness=1)
        card.place(relx=0.5, rely=0.45, anchor="center")
        inner = tk.Frame(card, bg=theme.CARD, padx=34, pady=28)
        inner.pack()

        self.build_heading(inner)
        self.username = self.add_field(inner, "Username")
        self.password = self.add_field(inner, "Password", secret=True)
        self.confirm = self.add_field(inner, "Confirm password", secret=True) if self.setup_mode else None
        self.error = tk.Label(inner, text="", fg=theme.BAD, bg=theme.CARD, wraplength=300,
                              justify="left", font=(theme.FONT, 9))
        self.error.pack(anchor="w", pady=(8, 0))
        label = "Create account and sign in" if self.setup_mode else "Sign in"
        ttk.Button(inner, text=label, style="Accent.TButton", command=self.submit).pack(
            fill="x", pady=(12, 0))
        self.username.focus_set()

    def build_heading(self, parent):
        title = "Create the administrator account" if self.setup_mode else "Sign in"
        tk.Label(parent, text=title, bg=theme.CARD, fg=theme.TEXT,
                 font=(theme.FONT, 16, "bold")).pack(anchor="w")
        hint = ("This is the first run. Choose a username and a password of at least "
                "10 characters. You can add other people afterwards."
                if self.setup_mode else "Use the account an administrator created for you.")
        tk.Label(parent, text=hint, bg=theme.CARD, fg=theme.MUTED, wraplength=300,
                 justify="left", font=(theme.FONT, 9)).pack(anchor="w", pady=(2, 8))

    def add_field(self, parent, label, secret=False):
        tk.Label(parent, text=label, bg=theme.CARD, fg=theme.TEXT,
                 font=(theme.FONT, 10, "bold")).pack(anchor="w", pady=(8, 2))
        entry = ttk.Entry(parent, width=32, font=(theme.FONT, 11), show="*" if secret else "")
        entry.pack(anchor="w")
        entry.bind("<Return>", lambda event: self.submit())
        return entry

    def submit(self):
        name, password = self.username.get(), self.password.get()
        try:
            if self.setup_mode:
                if password != self.confirm.get():
                    raise AuthError("MISMATCH", "The two passwords do not match.")
                self.app.auth.create_first_admin(name, password)
            session = self.app.auth.login(name, password)
        except AuthError as error:
            self.fail(error.message)
            return
        self.app.signed_in(session)

    def fail(self, message):
        self.error.config(text=message)
        self.password.delete(0, "end")
        if self.confirm is not None:
            self.confirm.delete(0, "end")
        self.password.focus_set()