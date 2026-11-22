import tkinter as tk
from tkinter import messagebox, ttk

from analysis.vuln_matcher import HAS_KEY
from auth.service import AuthError, AuthService
from auth.user_store import UserStore
from gui import theme
from gui.dialogs import FormDialog
from gui.login_view import LoginView
from gui.results_view import ResultsView
from gui.scan_view import ScanView
from gui.users_view import UsersView
from scanner.scope_guard import ScopeError, load_default_guard

FOOTER_BG = "#e6ebf1"
TAGLINE = "Scan a device, match its services to known CVEs and rank the risk"


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Vulnerability Assessment System")
        theme.setup_styles(self)
        theme.center_window(self, 1040, 760)
        self.minsize(900, 540)

        # remembered so "New Scan" comes back with the last target filled in
        self.last_target = "192.168.56.101"
        self.session = None
        self.auth = AuthService(UserStore())
        self.auth.store.init()
        self.load_guard()

        self.build_header()
        self.build_footer()
        self.container = tk.Frame(self, bg=theme.BG)
        self.container.pack(fill="both", expand=True)
        self.current_frame = None
        self.show_login_view()

    # ---------- start-up ----------

    def load_guard(self):
        """The signed scope decides what may be scanned. Without it, nothing is."""
        try:
            self.guard = load_default_guard()
            self.scope_problem = ""
        except ScopeError as error:
            self.guard = None
            self.scope_problem = f"{error} ({error.code})"

    def build_header(self):
        header = tk.Frame(self, bg=theme.NAVY)
        header.pack(fill="x")
        tk.Label(header, text="Network Vulnerability Assessment System", bg=theme.NAVY,
                 fg="white", font=(theme.FONT, 15, "bold")).pack(side="left", padx=(28, 0), pady=14)
        self.header_right = tk.Frame(header, bg=theme.NAVY)
        self.header_right.pack(side="right", padx=28)
        self.refresh_header()

    def build_footer(self):
        footer = tk.Frame(self, bg=FOOTER_BG)
        footer.pack(side="bottom", fill="x")
        if HAS_KEY:
            key_text, key_color = "NVD API key: loaded", theme.GOOD
        else:
            key_text, key_color = "NVD API key: missing (lookups will be slow)", theme.WARN
        tk.Label(footer, text=key_text, bg=FOOTER_BG, fg=key_color,
                 font=(theme.FONT, 9, "bold")).pack(side="left", padx=28, pady=6)
        if self.guard:
            scope_text, scope_color = f"Scope: {self.guard.describe()}", theme.GOOD
        else:
            scope_text, scope_color = "Scope NOT LOADED: scans are blocked", theme.BAD
        tk.Label(footer, text=scope_text, bg=FOOTER_BG, fg=scope_color,
                 font=(theme.FONT, 9, "bold")).pack(side="right", padx=28)

    # ---------- header: who is signed in ----------

    def refresh_header(self):
        for child in self.header_right.winfo_children():
            child.destroy()
        if self.session is None:
            tk.Label(self.header_right, text=TAGLINE, bg=theme.NAVY, fg="#b8c7dc",
                     font=(theme.FONT, 10)).pack()
            return
        tk.Label(self.header_right, text=f"{self.session.username}  ({self.session.role})",
                 bg=theme.NAVY, fg="white", font=(theme.FONT, 10, "bold")).pack(side="left", padx=(0, 12))
        actions = [("Change password", self.change_own_password), ("Sign out", self.sign_out)]
        if self.can("manage_users"):
            actions.insert(0, ("Users", self.show_users_view))
        for text, command in actions:
            ttk.Button(self.header_right, text=text, style="Header.TButton",
                       command=command).pack(side="left", padx=(0, 6))

    # ---------- permissions ----------

    def can(self, permission):
        return self.auth.allowed(self.session, permission)

    def require(self, permission):
        self.auth.require(self.session, permission)

    # ---------- signing in and out ----------

    def signed_in(self, session):
        self.session = session
        self.refresh_header()
        self.show_scan_view()

    def sign_out(self):
        if getattr(self.current_frame, "scanning", False):
            messagebox.showinfo("Scan running", "Wait for the scan to finish before signing out.")
            return
        self.auth.logout(self.session)
        self.session = None
        self.refresh_header()
        self.show_login_view()

    def change_own_password(self):
        answers = FormDialog.ask(self, "Change password", [
            ("old", "Current password", "password", None),
            ("new", "New password (at least 10 characters)", "password", None),
            ("confirm", "Confirm new password", "password", None)], "Change")
        if not answers:
            return
        if answers["new"] != answers["confirm"]:
            messagebox.showerror("Change password", "The two new passwords do not match.")
            return
        try:
            self.auth.change_own_password(self.session, answers["old"], answers["new"])
        except AuthError as error:
            messagebox.showerror("Change password", error.message)
            return
        messagebox.showinfo("Change password", "Your password was changed.")

    # ---------- screens ----------

    def switch_frame(self, frame_class, **kwargs):
        if self.current_frame is not None:
            self.current_frame.destroy()
        self.current_frame = frame_class(self.container, self, **kwargs)
        self.current_frame.pack(fill="both", expand=True)

    def show_login_view(self):
        self.switch_frame(LoginView)

    def show_users_view(self):
        self.switch_frame(UsersView)

    def show_scan_view(self):
        self.switch_frame(ScanView)

    def show_results_view(self, target, matched, info=None):
        self.switch_frame(ResultsView, target=target, matched=matched, info=info)