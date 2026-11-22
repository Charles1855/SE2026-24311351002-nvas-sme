"""
service.py - the rules for accounts, sign-in and permissions.

Roles (they match the people who use the tool):
  ADMIN     the SME owner: manages accounts, can scan
  OPERATOR  the IT officer or technician: can scan
  VIEWER    for example a compliance officer: can look at results, cannot scan

Safe defaults:
  - there is no built-in account: the first run creates an administrator
  - the same message is shown for a wrong password and an unknown user
  - 5 wrong passwords lock the account for 5 minutes
  - permissions are re-read from the database on every check, so disabling an
    account takes effect straight away
  - the last active administrator cannot be disabled or demoted
  - passwords never appear in the security-event log

Known limits: the lockout message shows that an account exists, and there is no
idle timeout yet.
"""
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from auth import passwords

ROLES = ("ADMIN", "OPERATOR", "VIEWER")
PERMISSIONS = {
    "scan": {"ADMIN", "OPERATOR"},
    "view_results": set(ROLES),
    "export_report": set(ROLES),
    "manage_users": {"ADMIN"},
}
MAX_FAILED_ATTEMPTS = 5
LOCK_MINUTES = 5
GENERIC_FAILURE = "Invalid username or password."
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{3,32}$")


class AuthError(Exception):
    """Something was refused. `code` says why and `message` is safe to show."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Session:
    username: str
    role: str
    started_at: datetime


class AuthService:
    def __init__(self, store, clock=None, log_n=passwords.LOG_N):
        self.store = store
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.log_n = log_n
        self._dummy_hash = None

    # ---------- helpers ----------

    def event(self, username, event, detail=""):
        self.store.log_event(self.clock().isoformat(), str(username)[:64], event, detail)

    def needs_setup(self):
        return self.store.count_users() == 0

    def _check_password(self, password, username):
        try:
            passwords.check_policy(password, username)
        except passwords.PasswordPolicyError as error:
            raise AuthError("WEAK_PASSWORD", str(error)) from error

    def _clean_username(self, username):
        text = username.strip() if isinstance(username, str) else ""
        if not USERNAME_PATTERN.match(text):
            raise AuthError("INVALID_USERNAME",
                            "Use 3 to 32 letters, digits, dots, dashes or underscores.")
        return text

    def _existing(self, username):
        user = self.store.get(str(username).strip())
        if user is None:
            raise AuthError("USER_NOT_FOUND", "There is no such user.")
        return user

    def _keep_one_admin(self, user):
        if user["role"] == "ADMIN" and user["active"] and self.store.count_active_admins() <= 1:
            raise AuthError("LAST_ADMIN", "Keep at least one active administrator.")

    # ---------- permissions ----------

    def allowed(self, session, permission):
        user = self.store.get(session.username) if session else None
        if user is None or not user["active"]:
            return False
        return user["role"] in PERMISSIONS.get(permission, ())

    def require(self, session, permission):
        if not self.allowed(session, permission):
            self.event(session.username if session else "", "PERMISSION_DENIED", permission)
            raise AuthError("PERMISSION_DENIED", "Your account is not allowed to do that.")

    # ---------- signing in ----------

    def create_first_admin(self, username, password):
        if not self.needs_setup():
            raise AuthError("SETUP_DONE", "An administrator already exists.")
        name = self._clean_username(username)
        self._check_password(password, name)
        self.store.add(name, passwords.hash_password(password, self.log_n),
                       "ADMIN", self.clock().isoformat())
        self.event(name, "FIRST_ADMIN_CREATED")

    def _dummy_check(self, password):
        """Do the same work for an unknown user, so timing does not give them away."""
        if self._dummy_hash is None:
            self._dummy_hash = passwords.hash_password("not-a-real-password", self.log_n)
        passwords.verify_password(password, self._dummy_hash)

    def _is_locked(self, user, now):
        return bool(user["locked_until"]) and now < datetime.fromisoformat(user["locked_until"])

    def _register_failure(self, user, now):
        attempts = user["failed_attempts"] + 1
        if attempts >= MAX_FAILED_ATTEMPTS:
            until = (now + timedelta(minutes=LOCK_MINUTES)).isoformat()
            self.store.record_failure(user["username"], 0, until)
            self.event(user["username"], "LOGIN_LOCKED_OUT", f"{LOCK_MINUTES} minutes")
        else:
            self.store.record_failure(user["username"], attempts, None)
            self.event(user["username"], "LOGIN_FAILED", f"attempt {attempts}")

    def login(self, username, password):
        now = self.clock()
        user = self.store.get(username.strip()) if isinstance(username, str) else None
        if user is None or not user["active"]:
            self._dummy_check(password)
            self.event(username, "LOGIN_FAILED", "unknown or disabled account")
            raise AuthError("INVALID_CREDENTIALS", GENERIC_FAILURE)
        if self._is_locked(user, now):
            self.event(user["username"], "LOGIN_BLOCKED", "account is locked")
            raise AuthError("ACCOUNT_LOCKED", f"Too many failed attempts. Try again in "
                                              f"{LOCK_MINUTES} minutes.")
        if not passwords.verify_password(password, user["password_hash"]):
            self._register_failure(user, now)
            raise AuthError("INVALID_CREDENTIALS", GENERIC_FAILURE)
        self.store.record_success(user["username"], now.isoformat())
        self.event(user["username"], "LOGIN_OK")
        return Session(user["username"], user["role"], now)

    def logout(self, session):
        self.event(session.username, "LOGOUT")

    # ---------- managing accounts (administrators only) ----------

    def create_user(self, actor, username, password, role):
        self.require(actor, "manage_users")
        name = self._clean_username(username)
        if role not in ROLES:
            raise AuthError("INVALID_ROLE", "Choose ADMIN, OPERATOR or VIEWER.")
        self._check_password(password, name)
        try:
            self.store.add(name, passwords.hash_password(password, self.log_n),
                           role, self.clock().isoformat())
        except sqlite3.IntegrityError as error:
            raise AuthError("USER_EXISTS", "That username is already taken.") from error
        self.event(actor.username, "USER_CREATED", f"{name} as {role}")

    def change_role(self, actor, username, role):
        self.require(actor, "manage_users")
        user = self._existing(username)
        if role not in ROLES:
            raise AuthError("INVALID_ROLE", "Choose ADMIN, OPERATOR or VIEWER.")
        if role != "ADMIN":
            self._keep_one_admin(user)
        self.store.set_role(user["username"], role)
        self.event(actor.username, "ROLE_CHANGED", f"{user['username']} to {role}")

    def set_active(self, actor, username, active):
        self.require(actor, "manage_users")
        user = self._existing(username)
        if not active:
            self._keep_one_admin(user)
        self.store.set_active(user["username"], active)
        self.event(actor.username, "USER_ENABLED" if active else "USER_DISABLED",
                   user["username"])

    def reset_password(self, actor, username, new_password):
        self.require(actor, "manage_users")
        user = self._existing(username)
        self._check_password(new_password, user["username"])
        self.store.update_password(user["username"],
                                   passwords.hash_password(new_password, self.log_n))
        self.event(actor.username, "PASSWORD_RESET", user["username"])

    def list_users(self, actor):
        self.require(actor, "manage_users")
        return self.store.list_users()

    def recent_events(self, actor, limit=15):
        self.require(actor, "manage_users")
        return self.store.recent_events(limit)

    # ---------- any signed-in user ----------

    def change_own_password(self, session, old_password, new_password):
        user = self.store.get(session.username)
        if user is None or not passwords.verify_password(old_password, user["password_hash"]):
            raise AuthError("WRONG_PASSWORD", "The current password is not correct.")
        self._check_password(new_password, user["username"])
        self.store.update_password(user["username"],
                                   passwords.hash_password(new_password, self.log_n))
        self.event(user["username"], "PASSWORD_CHANGED")