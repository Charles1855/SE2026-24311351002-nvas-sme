"""
user_store.py - the users and security-event tables (SQLite).

Only this module talks to the database about accounts. The rules (who may do
what, lockout, passwords) live in service.py.
"""
import sqlite3
from contextlib import closing

from database.db import get_connection

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('ADMIN', 'OPERATOR', 'VIEWER')),
    active INTEGER NOT NULL DEFAULT 1,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL,
    last_login TEXT
);
CREATE TABLE IF NOT EXISTS auth_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL,
    username TEXT,
    event TEXT NOT NULL,
    detail TEXT
);
"""


class UserStore:
    def __init__(self, connect=None):
        self.connect = connect or get_connection

    def init(self):
        with closing(self.connect()) as conn:
            conn.executescript(SCHEMA)

    # ---------- small helpers ----------

    def _query(self, sql, params=(), one=False):
        with closing(self.connect()) as conn:
            conn.row_factory = sqlite3.Row
            rows = [dict(row) for row in conn.execute(sql, params).fetchall()]
        if one:
            return rows[0] if rows else None
        return rows

    def _execute(self, sql, params=()):
        with closing(self.connect()) as conn, conn:
            conn.execute(sql, params)

    # ---------- reading ----------

    def count_users(self):
        return self._query("SELECT COUNT(*) AS n FROM users", one=True)["n"]

    def count_active_admins(self):
        sql = "SELECT COUNT(*) AS n FROM users WHERE role = 'ADMIN' AND active = 1"
        return self._query(sql, one=True)["n"]

    def get(self, username):
        return self._query("SELECT * FROM users WHERE username = ?", (username,), one=True)

    def list_users(self):
        return self._query(
            "SELECT username, role, active, last_login, created_at "
            "FROM users ORDER BY username COLLATE NOCASE")

    def recent_events(self, limit):
        return self._query(
            "SELECT time, username, event, detail FROM auth_events ORDER BY id DESC LIMIT ?",
            (limit,))

    # ---------- changing ----------

    def add(self, username, password_hash, role, created_at):
        self._execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, password_hash, role, created_at))

    def update_password(self, username, password_hash):
        self._execute(
            "UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL "
            "WHERE username = ?", (password_hash, username))

    def set_active(self, username, active):
        self._execute("UPDATE users SET active = ? WHERE username = ?",
                      (1 if active else 0, username))

    def set_role(self, username, role):
        self._execute("UPDATE users SET role = ? WHERE username = ?", (role, username))

    def record_failure(self, username, attempts, locked_until):
        self._execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?",
                      (attempts, locked_until, username))

    def record_success(self, username, when):
        self._execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ? "
            "WHERE username = ?", (when, username))

    def log_event(self, when, username, event, detail):
        self._execute("INSERT INTO auth_events (time, username, event, detail) VALUES (?, ?, ?, ?)",
                      (when, username, event, detail))