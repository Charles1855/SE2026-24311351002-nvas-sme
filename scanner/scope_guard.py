"""
scope_guard.py
Scope enforcement: the scanner may only touch targets listed in a signed
authorisation file. Anything else is refused BEFORE any network activity.

Every rule refuses by default. If anything is unclear, the answer is no.
  - the scope file must carry a valid Ed25519 signature from the trusted authoriser
  - the scope must be inside its validity window and must not be too broad
  - the target must be an IP address or a CIDR range (host names are refused,
    because looking one up is itself network traffic)
  - the target must sit fully inside one of the authorised networks
"""
import base64
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCOPE_PATH = ROOT / "scope" / "scope.json"
DEFAULT_KEY_PATH = ROOT / "scope" / "authoriser_public.pem"
DEFAULT_AUDIT_PATH = ROOT / "logs" / "scope_audit.log"

MAX_TARGET_LENGTH = 100
# A scope may not be broader than this (a /16 is 65,536 addresses)
MIN_PREFIX = {4: 16, 6: 48}


class ScopeError(Exception):
    """A target or a scope file was refused. `code` says why."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Scope:
    organisation: str
    authorised_by: str
    networks: tuple
    not_before: datetime
    not_after: datetime


# ---------- signing and loading the scope file ----------

def canonical_bytes(scope_data):
    """The exact bytes that are signed: sorted keys, no spaces."""
    return json.dumps(scope_data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_scope(scope_data, private_key):
    """Used by scope_tool.py when the authoriser signs a scope."""
    return base64.b64encode(private_key.sign(canonical_bytes(scope_data))).decode("ascii")


def load_public_key(path):
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except (OSError, ValueError, UnsupportedAlgorithm) as error:
        raise ScopeError("SCOPE_MISSING",
                         f"Cannot read the authoriser's public key: {error}") from error
    if not isinstance(key, Ed25519PublicKey):
        raise ScopeError("SCOPE_MALFORMED", "The public key is not an Ed25519 key.")
    return key


def read_scope_file(path):
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as error:
        raise ScopeError("SCOPE_MISSING", f"Cannot read the scope file: {error}") from error
    except ValueError as error:
        raise ScopeError("SCOPE_MALFORMED", "The scope file is not valid JSON.") from error
    if (not isinstance(document, dict)
            or not isinstance(document.get("scope"), dict)
            or not isinstance(document.get("signature"), str)):
        raise ScopeError("SCOPE_MALFORMED",
                         "The scope file needs a 'scope' and a 'signature' entry.")
    return document


def verify_signature(document, public_key):
    try:
        signature = base64.b64decode(document["signature"], validate=True)
        public_key.verify(signature, canonical_bytes(document["scope"]))
    except (ValueError, InvalidSignature) as error:
        raise ScopeError("SIGNATURE_INVALID",
                         "The scope file's signature does not match. It was changed, "
                         "or it was signed by someone else.") from error


def parse_time(value, field):
    try:
        moment = datetime.fromisoformat(value)
    except (TypeError, ValueError) as error:
        raise ScopeError("SCOPE_MALFORMED", f"'{field}' is not a valid date and time.") from error
    if moment.tzinfo is None:
        raise ScopeError("SCOPE_MALFORMED",
                         f"'{field}' needs a time zone, for example +00:00.")
    return moment


def parse_networks(values):
    if not isinstance(values, list) or not values:
        raise ScopeError("SCOPE_MALFORMED", "The scope lists no networks.")
    networks = []
    for value in values:
        if not isinstance(value, str):
            raise ScopeError("SCOPE_MALFORMED", f"'{value}' is not a valid network.")
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as error:
            raise ScopeError("SCOPE_MALFORMED", f"'{value}' is not a valid network.") from error
        if network.prefixlen < MIN_PREFIX[network.version]:
            raise ScopeError("SCOPE_TOO_BROAD",
                             f"{network} is broader than a /{MIN_PREFIX[network.version]}. "
                             "Scopes must be narrower than that.")
        networks.append(network)
    return tuple(networks)


def parse_scope(data):
    for field in ("organisation", "authorised_by"):
        if not isinstance(data.get(field), str) or not data[field].strip():
            raise ScopeError("SCOPE_MALFORMED", f"'{field}' is missing.")
    scope = Scope(
        organisation=data["organisation"].strip(),
        authorised_by=data["authorised_by"].strip(),
        networks=parse_networks(data.get("networks")),
        not_before=parse_time(data.get("not_before"), "not_before"),
        not_after=parse_time(data.get("not_after"), "not_after"),
    )
    if scope.not_before >= scope.not_after:
        raise ScopeError("SCOPE_MALFORMED", "'not_before' must be earlier than 'not_after'.")
    return scope


def load_scope(scope_path, public_key_path):
    """Check the signature first, and only then trust what the file says."""
    document = read_scope_file(scope_path)
    verify_signature(document, load_public_key(public_key_path))
    return parse_scope(document["scope"])


# ---------- checking a target ----------

def parse_target(text):
    if not isinstance(text, str):
        raise ScopeError("INVALID_TARGET", "The target must be text.")
    text = text.strip()
    if not text or len(text) > MAX_TARGET_LENGTH:
        raise ScopeError("INVALID_TARGET", "The target is empty or too long.")
    if any(character.isspace() for character in text):
        raise ScopeError("INVALID_TARGET", "The target must not contain spaces.")
    try:
        return ipaddress.ip_network(text, strict=True)
    except ValueError as error:
        raise ScopeError("INVALID_TARGET",
                         "Enter an IP address or a CIDR range such as 192.168.56.0/24. "
                         "Host names are not accepted.") from error


def inside_scope(target, scope):
    return any(
        network.version == target.version and target.subnet_of(network)
        for network in scope.networks
    )


def describe_network(network):
    """A single address reads better without its /32 (or /128)."""
    return str(network.network_address) if network.num_addresses == 1 else str(network)


_TOKEN = object()


class ValidatedTarget:
    """A target that passed the guard. Only ScopeGuard.authorise() can create one."""

    def __init__(self, network, token):
        if token is not _TOKEN:
            raise TypeError("A ValidatedTarget can only come from ScopeGuard.authorise().")
        self.network = network

    @property
    def is_single_host(self):
        return self.network.num_addresses == 1

    @property
    def address(self):
        return str(self.network.network_address)

    def __str__(self):
        return self.address if self.is_single_host else str(self.network)


class ScopeGuard:
    def __init__(self, scope, clock=None, audit_path=None):
        self.scope = scope
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.audit_path = Path(audit_path) if audit_path else None
        self.audit = []

    @classmethod
    def from_files(cls, scope_path, public_key_path, **options):
        return cls(load_scope(scope_path, public_key_path), **options)

    def authorise(self, target_text):
        """Return a ValidatedTarget, or raise ScopeError. Never touches the network."""
        try:
            network = parse_target(target_text)
            self.check_window()
            if not inside_scope(network, self.scope):
                raise ScopeError("OUT_OF_SCOPE",
                                 f"{describe_network(network)} is outside the authorised "
                                 f"scope of {self.scope.organisation}.")
        except ScopeError as error:
            self.record(target_text, "REFUSED", error.code)
            raise
        self.record(target_text, "ALLOWED", "IN_SCOPE")
        return ValidatedTarget(network, _TOKEN)

    def check_window(self):
        now = self.clock()
        if now < self.scope.not_before:
            raise ScopeError("SCOPE_NOT_YET_VALID", "The scope file is not valid yet.")
        if now > self.scope.not_after:
            raise ScopeError("SCOPE_EXPIRED",
                             "The scope file has expired. Ask the authoriser for a new one.")

    def record(self, target_text, decision, code):
        entry = {
            "time": self.clock().isoformat(),
            "target": str(target_text)[:200],
            "decision": decision,
            "code": code,
            "organisation": self.scope.organisation,
        }
        self.audit.append(entry)
        if self.audit_path:
            self.write_audit_line(entry)

    def write_audit_line(self, entry):
        try:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")
        except OSError:
            pass  # a full disk must not turn a refusal into a crash

    def describe(self):
        networks = ", ".join(str(network) for network in self.scope.networks)
        return (f"{self.scope.organisation} | {networks} | "
                f"valid until {self.scope.not_after:%d %b %Y}")


def load_default_guard():
    """The guard the app uses: scope/scope.json checked against scope/authoriser_public.pem."""
    return ScopeGuard.from_files(DEFAULT_SCOPE_PATH, DEFAULT_KEY_PATH,
                                 audit_path=DEFAULT_AUDIT_PATH)