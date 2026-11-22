import tkinter as tk
from tkinter import messagebox, ttk

from auth.service import ROLES, AuthError
from gui import theme
from gui.dialogs import FormDialog

COLUMNS = (("username", "Username", 200), ("role", "Role", 110),
           ("status", "Status", 110), ("last_login", "Last sign-in (UTC)", 220))


class UsersView(tk.Frame):
    """Administrators only: accounts, roles and the recent security events."""

    def __init__(self, parent, app):
        super().__init__(parent, bg=theme.BG, padx=32, pady=14)
        self.app = app
        self.users = {}
        self.build_title()
        self.build_table()
        self.build_buttons()
        self.build_events()
        self.refresh()

    # ---------- layout ----------

    def build_title(self):
        top = tk.Frame(self, bg=theme.BG)
        top.pack(fill="x")
        tk.Label(top, text="User management", bg=theme.BG, fg=theme.TEXT,
                 font=(theme.FONT, 20, "bold")).pack(side="left")
        ttk.Button(top, text="Back to scan", command=self.app.show_scan_view).pack(side="right")
        tk.Label(self, text="ADMIN manages accounts and can scan. OPERATOR can scan. "
                            "VIEWER can look at results but cannot scan.",
                 bg=theme.BG, fg=theme.MUTED, font=(theme.FONT, 10)).pack(anchor="w", pady=(0, 8))

    def build_table(self):
        frame = tk.Frame(self, bg=theme.CARD, highlightbackground=theme.BORDER,
                         highlightcolor=theme.BORDER, highlightthickness=1)
        frame.pack(fill="x")
        self.table = ttk.Treeview(frame, columns=[c[0] for c in COLUMNS], show="headings",
                                  height=5, selectmode="browse")
        for key, title, width in COLUMNS:
            self.table.heading(key, text=title)
            self.table.column(key, width=width, anchor="w")
        self.table.pack(fill="x")

    def build_buttons(self):
        row = tk.Frame(self, bg=theme.BG)
        row.pack(fill="x", pady=(10, 0))
        ttk.Button(row, text="Add user", style="Accent.TButton",
                   command=self.add_user).pack(side="left")
        for text, command in [("Change role", self.change_role),
                              ("Disable / enable", self.toggle_active),
                              ("Reset password", self.reset_password)]:
            ttk.Button(row, text=text, command=command).pack(side="left", padx=(8, 0))

    def build_events(self):
        tk.Label(self, text="Recent security events", bg=theme.BG, fg=theme.TEXT,
                 font=(theme.FONT, 10, "bold")).pack(anchor="w", pady=(14, 4))
        frame = tk.Frame(self, bg=theme.CARD, highlightbackground=theme.BORDER,
                         highlightcolor=theme.BORDER, highlightthickness=1)
        frame.pack(fill="both", expand=True)
        self.events = tk.Text(frame, height=6, font=(theme.MONO, 9), bg=theme.CARD,
                              relief="flat", padx=10, pady=6, state="disabled")
        self.events.pack(fill="both", expand=True)

    # ---------- showing data ----------

    def refresh(self):
        try:
            users = self.app.auth.list_users(self.app.session)
            events = self.app.auth.recent_events(self.app.session, 15)
        except AuthError as error:
            messagebox.showerror("Not allowed", error.message)
            self.app.show_scan_view()
            return
        self.fill_table(users)
        self.fill_events(events)

    def fill_table(self, users):
        self.table.delete(*self.table.get_children())
        self.users = {user["username"]: user for user in users}
        for user in users:
            last = (user["last_login"] or "never")[:16].replace("T", " ")
            status = "Active" if user["active"] else "Disabled"
            self.table.insert("", "end", iid=user["username"],
                              values=(user["username"], user["role"], status, last))

    def fill_events(self, events):
        lines = [f"{e['time'][:19].replace('T', ' ')}  {e['event']:<18} "
                 f"{(e['username'] or '-'):<14} {e['detail'] or ''}" for e in events]
        self.events.config(state="normal")
        self.events.delete("1.0", "end")
        self.events.insert("end", "\n".join(lines))
        self.events.config(state="disabled")

    # ---------- actions ----------

    def selected(self):
        chosen = self.table.selection()
        if not chosen:
            messagebox.showinfo("Choose a user", "Click a user in the list first.")
            return None
        return chosen[0]

    def act(self, action, *args):
        try:
            action(self.app.session, *args)
        except AuthError as error:
            messagebox.showerror("That did not work", error.message)
        self.refresh()

    def add_user(self):
        answers = FormDialog.ask(self, "Add user", [
            ("username", "Username", "text", None),
            ("role", "Role", "choice", ROLES),
            ("password", "Password (at least 10 characters)", "password", None),
        ], "Add user")
        if answers:
            self.act(self.app.auth.create_user, answers["username"],
                     answers["password"], answers["role"])

    def change_role(self):
        name = self.selected()
        answers = name and FormDialog.ask(self, f"Role for {name}", [
            ("role", "Role", "choice", ROLES)], "Save")
        if answers:
            self.act(self.app.auth.change_role, name, answers["role"])

    def toggle_active(self):
        name = self.selected()
        if name:
            self.act(self.app.auth.set_active, name, not self.users[name]["active"])

    def reset_password(self):
        name = self.selected()
        answers = name and FormDialog.ask(self, f"New password for {name}", [
            ("password", "New password", "password", None),
            ("confirm", "Confirm password", "password", None)], "Reset")
        if not answers:
            return
        if answers["password"] != answers["confirm"]:
            messagebox.showerror("That did not work", "The two passwords do not match.")
            return
        self.act(self.app.auth.reset_password, name, answers["password"])