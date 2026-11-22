import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from unittest import mock

import nmap
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auth.service import AuthService
from auth.user_store import UserStore
from test_scope_guard import EngineSpy, public_pem


def before_scenario(context, scenario):
    context.folder = tempfile.TemporaryDirectory()
    context.trusted_key = Ed25519PrivateKey.generate()
    context.signer = context.trusted_key
    context.public_path = os.path.join(context.folder.name, "public.pem")
    context.scope_path = os.path.join(context.folder.name, "scope.json")
    with open(context.public_path, "wb") as handle:
        handle.write(public_pem(context.trusted_key))

    context.scope = None
    context.tamper = None
    context.no_file = False
    context.error = None
    context.guard = None
    context.now = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)

    # a fresh, empty account database (cheap password hashing keeps the scenarios fast)
    database_path = os.path.join(context.folder.name, "accounts.db")
    context.store = UserStore(lambda: sqlite3.connect(database_path))
    context.store.init()
    context.auth = AuthService(context.store, clock=lambda: context.now, log_n=4)
    context.passwords = {}
    context.sessions = {}
    context.auth_error = None
    context.auth_session = None

    # nmap is replaced by a spy that counts every use
    context.spy = EngineSpy()
    context.patch = mock.patch.object(nmap, "PortScanner", context.spy)
    context.patch.start()


def after_scenario(context, scenario):
    context.patch.stop()
    context.folder.cleanup()