"""
scope_tool.py - create, sign and check the authorisation scope file.

  python scope_tool.py keygen
  python scope_tool.py sign --organisation "Demo SME Ltd" --authorised-by "A. Owner, Owner" --network 192.168.56.0/24
  python scope_tool.py check --target 192.168.56.102
  python scope_tool.py demo

The authoriser (for example the SME owner) keeps scope/authoriser_private.pem
and signs the scope. The scanner only holds the public key, so it can check a
scope file but can never create one.
"""
import argparse
import json
import time
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scanner.port_scanner import PortScanner
from scanner.scope_guard import (
    DEFAULT_KEY_PATH,
    DEFAULT_SCOPE_PATH,
    ScopeError,
    load_default_guard,
    parse_scope,
    sign_scope,
)

PRIVATE_KEY_PATH = DEFAULT_KEY_PATH.with_name("authoriser_private.pem")

# 20 attempts that must all be refused. The addresses are private or reserved for
# documentation (RFC 5737), so even a bug could not send anything to a real host.
DEMO_TARGETS = [
    "192.168.57.1", "192.168.55.255", "192.168.56.0/23", "10.0.0.5", "172.16.0.1",
    "192.0.2.10", "198.51.100.7", "203.0.113.9", "0.0.0.0/0", "127.0.0.1",
    "2001:db8::1", "192.168.56.5/24", "192.168.56.256", "192.168.056.001", "localhost",
    "example.com", "192.168.56.1-50", "192.168.56.1 --script vuln",
    "http://192.168.56.1", "192.168.56.1:80",
]


def keygen(args):
    if (PRIVATE_KEY_PATH.exists() or DEFAULT_KEY_PATH.exists()) and not args.force:
        print("Keys already exist. Use --force to replace them "
              "(scope files signed with the old key will stop working).")
        return 1
    private_key = Ed25519PrivateKey.generate()
    DEFAULT_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    PRIVATE_KEY_PATH.write_bytes(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    DEFAULT_KEY_PATH.write_bytes(private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    print(f"Private key (keep it secret, never commit it): {PRIVATE_KEY_PATH}")
    print(f"Public key (safe to commit):                   {DEFAULT_KEY_PATH}")
    return 0


def sign(args):
    if not PRIVATE_KEY_PATH.exists():
        print("There is no private key yet. Run:  python scope_tool.py keygen")
        return 1
    private_key = serialization.load_pem_private_key(PRIVATE_KEY_PATH.read_bytes(), password=None)

    # start one minute in the past so a small clock difference cannot matter
    start = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=1)
    scope = {
        "organisation": args.organisation,
        "authorised_by": args.authorised_by,
        "networks": args.network,
        "not_before": start.isoformat(),
        "not_after": (start + timedelta(days=args.days)).isoformat(),
    }
    try:
        parse_scope(scope)  # never sign something the guard would reject
    except ScopeError as error:
        print(f"Not signed ({error.code}): {error}")
        return 1

    document = {"scope": scope, "signature": sign_scope(scope, private_key)}
    DEFAULT_SCOPE_PATH.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"Signed scope written to {DEFAULT_SCOPE_PATH}")
    return check(argparse.Namespace(target=None))


def check(args):
    try:
        guard = load_default_guard()
    except ScopeError as error:
        print(f"SCOPE NOT LOADED ({error.code}): {error}")
        return 1
    print(f"Scope OK: {guard.describe()}")
    if not args.target:
        return 0
    try:
        validated = guard.authorise(args.target)
    except ScopeError as error:
        print(f"REFUSED ({error.code}): {error}")
        return 2
    print(f"ALLOWED: {validated}")
    return 0


def demo(args):
    """Send 20 out-of-scope attempts through the real scanner. Capture traffic while it runs."""
    try:
        scanner = PortScanner(load_default_guard())
    except ScopeError as error:
        print(f"SCOPE NOT LOADED ({error.code}): {error}")
        return 1

    refused = 0
    for number, target in enumerate(DEMO_TARGETS, start=1):
        try:
            scanner.scan_target(target)
            print(f"{number:>2}. {target:<30} NOT REFUSED  <-- this is a bug")
        except ScopeError as error:
            refused += 1
            print(f"{number:>2}. {target:<30} refused ({error.code})")
        time.sleep(args.pause)
    print(f"\nRefused {refused} of {len(DEMO_TARGETS)}. nmap was never started for a refused target.")
    return 0 if refused == len(DEMO_TARGETS) else 3


def build_parser():
    parser = argparse.ArgumentParser(description="Create, sign and check the scope file.")
    commands = parser.add_subparsers(dest="command", required=True)

    keys = commands.add_parser("keygen", help="create the authoriser's key pair")
    keys.add_argument("--force", action="store_true", help="replace existing keys")
    keys.set_defaults(run=keygen)

    signing = commands.add_parser("sign", help="sign a new scope file")
    signing.add_argument("--organisation", required=True)
    signing.add_argument("--authorised-by", required=True)
    signing.add_argument("--network", action="append", required=True,
                         help="authorised network, e.g. 192.168.56.0/24 (repeat for more)")
    signing.add_argument("--days", type=int, default=365, help="how long the scope is valid")
    signing.set_defaults(run=sign)

    checking = commands.add_parser("check", help="load the scope and test one target")
    checking.add_argument("--target", help="an IP address or CIDR range to test")
    checking.set_defaults(run=check)

    showing = commands.add_parser("demo", help="run 20 out-of-scope attempts")
    showing.add_argument("--pause", type=float, default=0.0,
                         help="seconds between attempts, useful while capturing")
    showing.set_defaults(run=demo)
    return parser


if __name__ == "__main__":
    arguments = build_parser().parse_args()
    raise SystemExit(arguments.run(arguments))