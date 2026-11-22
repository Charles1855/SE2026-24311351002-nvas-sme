"""
passwords.py - storing and checking passwords.

A password is never stored. We store a scrypt hash with its own random salt,
using the minimum cost OWASP recommends when Argon2id is not available
(N = 2^17, r = 8, p = 1, which needs 128 MiB of memory per hash).

Stored format:  scrypt$<log2 N>$<r>$<p>$<salt in base64>$<hash in base64>
The cost is stored inside the string, so it can be raised later without
breaking existing accounts.
"""
import base64
import hashlib
import hmac
import secrets

LOG_N = 17
BLOCK_SIZE = 8
PARALLEL = 1
SALT_BYTES = 16
KEY_BYTES = 32

MIN_LENGTH = 10
MAX_LENGTH = 128
MIN_DISTINCT = 4

# A small blocklist of passwords that long enough to pass the length rule
COMMON_PASSWORDS = {
    "1234567890", "0123456789", "qwertyuiop", "qwerty12345", "1q2w3e4r5t",
    "abcdefghij", "password123", "password1234", "passw0rd123", "adminadmin",
    "administrator", "welcome123", "changeme123", "letmein1234", "iloveyou123",
}


class PasswordPolicyError(ValueError):
    """The password is not acceptable. The message says why."""


def check_policy(password, username=""):
    if not isinstance(password, str):
        raise PasswordPolicyError("The password must be text.")
    if len(password) < MIN_LENGTH:
        raise PasswordPolicyError(f"Use at least {MIN_LENGTH} characters.")
    if len(password) > MAX_LENGTH:
        raise PasswordPolicyError(f"Use at most {MAX_LENGTH} characters.")
    if len(set(password)) < MIN_DISTINCT:
        raise PasswordPolicyError(f"Use at least {MIN_DISTINCT} different characters.")
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS or lowered == str(username).strip().lower():
        raise PasswordPolicyError("That password is too easy to guess.")


def _derive(password, salt, log_n, block_size, parallel):
    memory = 128 * block_size * (2 ** log_n + parallel + 2) + 1024 * 1024
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2 ** log_n,
                          r=block_size, p=parallel, maxmem=memory, dklen=KEY_BYTES)


def hash_password(password, log_n=LOG_N):
    salt = secrets.token_bytes(SALT_BYTES)
    key = _derive(password, salt, log_n, BLOCK_SIZE, PARALLEL)
    parts = ["scrypt", str(log_n), str(BLOCK_SIZE), str(PARALLEL),
             base64.b64encode(salt).decode("ascii"), base64.b64encode(key).decode("ascii")]
    return "$".join(parts)


def verify_password(password, stored):
    """True only if the password matches. Any damaged or odd input gives False."""
    try:
        scheme, log_n, block_size, parallel, salt, key = stored.split("$")
        if scheme != "scrypt":
            return False
        log_n, block_size, parallel = int(log_n), int(block_size), int(parallel)
        if not (4 <= log_n <= 18 and 1 <= block_size <= 16 and 1 <= parallel <= 4):
            return False
        expected = base64.b64decode(key, validate=True)
        salt_bytes = base64.b64decode(salt, validate=True)
        candidate = _derive(password, salt_bytes, log_n, block_size, parallel)
    except (ValueError, TypeError, AttributeError):
        return False
    return hmac.compare_digest(candidate, expected)