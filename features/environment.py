import os
import tempfile
from datetime import datetime, timezone
from unittest import mock

import nmap
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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

    # nmap is replaced by a spy that counts every use
    context.spy = EngineSpy()
    context.patch = mock.patch.object(nmap, "PortScanner", context.spy)
    context.patch.start()


def after_scenario(context, scenario):
    context.patch.stop()
    context.folder.cleanup()