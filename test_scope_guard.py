"""
Tests for scope enforcement (the first Signature Challenge property).

Run from the project root:
    python -m unittest test_scope_guard -v
"""
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import nmap
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scanner.port_scanner import PortScanner
from scanner.scope_guard import (
    ScopeError,
    ScopeGuard,
    ValidatedTarget,
    load_scope,
    sign_scope,
)

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)

# 20 attempts that must all be refused (the card's "20 out-of-scope attempts")
TWENTY_REFUSALS = [
    "192.168.57.1", "192.168.55.255", "192.168.56.0/23", "10.0.0.5", "172.16.0.1",
    "192.0.2.10", "198.51.100.7", "203.0.113.9", "0.0.0.0/0", "127.0.0.1",
    "2001:db8::1", "192.168.56.5/24", "192.168.56.256", "192.168.056.001", "localhost",
    "example.com", "192.168.56.1-50", "192.168.56.1 --script vuln",
    "http://192.168.56.1", "192.168.56.1:80",
]


def make_scope(**changes):
    scope = {
        "organisation": "Demo SME Ltd",
        "authorised_by": "A. Owner, Owner",
        "networks": ["192.168.56.0/24"],
        "not_before": (NOW - timedelta(days=1)).isoformat(),
        "not_after": (NOW + timedelta(days=30)).isoformat(),
    }
    scope.update(changes)
    return scope


def public_pem(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


class ScopeFixture(unittest.TestCase):
    """Creates a key pair and a signed scope file in a temporary folder."""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.key = Ed25519PrivateKey.generate()
        self.public_path = os.path.join(self.folder.name, "public.pem")
        self.scope_path = os.path.join(self.folder.name, "scope.json")
        with open(self.public_path, "wb") as handle:
            handle.write(public_pem(self.key))

    def tearDown(self):
        self.folder.cleanup()

    def write_scope(self, scope=None, key=None, tamper=None):
        scope = scope or make_scope()
        document = {"scope": scope, "signature": sign_scope(scope, key or self.key)}
        if tamper:
            tamper(document)
        with open(self.scope_path, "w", encoding="utf-8") as handle:
            json.dump(document, handle)

    def guard(self, scope=None, **kwargs):
        self.write_scope(scope)
        kwargs.setdefault("clock", lambda: NOW)
        return ScopeGuard.from_files(self.scope_path, self.public_path, **kwargs)

    def assert_refused(self, guard, target, code):
        with self.assertRaises(ScopeError) as caught:
            guard.authorise(target)
        self.assertEqual(caught.exception.code, code, f"{target!r}")


class TargetClassesTests(ScopeFixture):
    """Equivalence classes: in scope, out of scope, malformed."""

    def test_in_scope_targets_are_accepted(self):
        guard = self.guard()
        for target in ["192.168.56.1", "192.168.56.254", "192.168.56.0", "192.168.56.255",
                       "192.168.56.0/24", "192.168.56.128/25", "192.168.56.7/32",
                       "  192.168.56.9  "]:
            with self.subTest(target=target):
                self.assertIsInstance(guard.authorise(target), ValidatedTarget)

    def test_out_of_scope_targets_are_refused(self):
        guard = self.guard()
        for target in ["192.168.55.255", "192.168.57.0", "192.168.56.0/23", "192.168.0.0/16",
                       "0.0.0.0/0", "8.8.8.8", "127.0.0.1", "10.1.2.3", "2001:db8::1"]:
            with self.subTest(target=target):
                self.assert_refused(guard, target, "OUT_OF_SCOPE")

    def test_malformed_targets_are_refused(self):
        guard = self.guard()
        malformed = [
            "", "   ", "localhost", "example.com", "192.168.56", "192.168.56.256",
            "192.168.056.001", "192.168.56.5/24", "192.168.56.0/33", "192.168.56.1-50",
            "192.168.56.1 --script vuln", "-iL targets.txt", "--script=vuln",
            "http://192.168.56.1", "192.168.56.1:80", "192.168.56.1;ls",
            "\uff11\uff19\uff12.168.56.1", "a" * 500, None, 12345, ["192.168.56.1"],
        ]
        for target in malformed:
            with self.subTest(target=target):
                self.assert_refused(guard, target, "INVALID_TARGET")

    def test_boundary_of_the_authorised_range(self):
        guard = self.guard()
        self.assertEqual(guard.authorise("192.168.56.255").address, "192.168.56.255")
        self.assert_refused(guard, "192.168.57.0", "OUT_OF_SCOPE")
        self.assert_refused(guard, "192.168.55.255", "OUT_OF_SCOPE")

    def test_ipv6_scope_and_mixed_versions(self):
        guard = self.guard(make_scope(networks=["2001:db8:abcd::/48"]))
        self.assertTrue(guard.authorise("2001:db8:abcd::1").address)
        self.assert_refused(guard, "2001:db8:abcf::1", "OUT_OF_SCOPE")
        self.assert_refused(guard, "192.168.56.1", "OUT_OF_SCOPE")  # no crash on mixed versions

    def test_several_networks_in_one_scope(self):
        guard = self.guard(make_scope(networks=["192.168.56.0/24", "10.20.0.0/24"]))
        self.assertTrue(guard.authorise("10.20.0.9").address)
        self.assert_refused(guard, "10.21.0.9", "OUT_OF_SCOPE")


class ScopeFileTests(ScopeFixture):
    def test_valid_file_loads(self):
        self.write_scope()
        scope = load_scope(self.scope_path, self.public_path)
        self.assertEqual(scope.organisation, "Demo SME Ltd")
        self.assertEqual([str(n) for n in scope.networks], ["192.168.56.0/24"])

    def assert_load_fails(self, code):
        with self.assertRaises(ScopeError) as caught:
            load_scope(self.scope_path, self.public_path)
        self.assertEqual(caught.exception.code, code)

    def test_changing_the_networks_after_signing_is_detected(self):
        self.write_scope(tamper=lambda d: d["scope"].update(networks=["10.0.0.0/24"]))
        self.assert_load_fails("SIGNATURE_INVALID")

    def test_changing_the_dates_after_signing_is_detected(self):
        far = (NOW + timedelta(days=9999)).isoformat()
        self.write_scope(tamper=lambda d: d["scope"].update(not_after=far))
        self.assert_load_fails("SIGNATURE_INVALID")

    def test_signed_by_someone_else_is_refused(self):
        self.write_scope(key=Ed25519PrivateKey.generate())
        self.assert_load_fails("SIGNATURE_INVALID")

    def test_garbage_signature_is_refused(self):
        self.write_scope(tamper=lambda d: d.update(signature="not base64 !!"))
        self.assert_load_fails("SIGNATURE_INVALID")

    def test_missing_signature_is_malformed(self):
        self.write_scope(tamper=lambda d: d.pop("signature"))
        self.assert_load_fails("SCOPE_MALFORMED")

    def test_file_that_is_not_json(self):
        with open(self.scope_path, "w") as handle:
            handle.write("{ this is not json")
        self.assert_load_fails("SCOPE_MALFORMED")

    def test_json_that_is_not_an_object(self):
        with open(self.scope_path, "w") as handle:
            handle.write("[1, 2, 3]")
        self.assert_load_fails("SCOPE_MALFORMED")

    def test_missing_scope_file(self):
        self.assert_load_fails("SCOPE_MISSING")

    def test_missing_or_unreadable_public_key(self):
        self.write_scope()
        os.remove(self.public_path)
        self.assert_load_fails("SCOPE_MISSING")
        with open(self.public_path, "w") as handle:
            handle.write("not a key")
        self.assert_load_fails("SCOPE_MISSING")

    def test_public_key_of_the_wrong_type(self):
        self.write_scope()
        wrong = ec.generate_private_key(ec.SECP256R1())
        with open(self.public_path, "wb") as handle:
            handle.write(public_pem(wrong))
        self.assert_load_fails("SCOPE_MALFORMED")

    def test_scopes_that_are_too_broad_are_refused(self):
        for network in ["0.0.0.0/0", "10.0.0.0/8", "192.168.0.0/15", "::/0", "2001:db8::/32"]:
            with self.subTest(network=network):
                self.write_scope(make_scope(networks=[network]))
                self.assert_load_fails("SCOPE_TOO_BROAD")

    def test_broadest_allowed_scope_is_a_slash_16(self):
        self.write_scope(make_scope(networks=["192.168.0.0/16"]))
        self.assertEqual(len(load_scope(self.scope_path, self.public_path).networks), 1)

    def test_malformed_contents_are_refused(self):
        bad_scopes = [
            make_scope(networks=[]), make_scope(networks="192.168.56.0/24"),
            make_scope(networks=[3232249856]), make_scope(networks=["not-a-network"]),
            make_scope(networks=["192.168.56.5/24"]), make_scope(organisation=""),
            make_scope(authorised_by=None), make_scope(not_before="2026-01-01T00:00:00"),
            make_scope(not_after="tomorrow"),
            make_scope(not_before=NOW.isoformat(), not_after=NOW.isoformat()),
            make_scope(not_before=(NOW + timedelta(days=40)).isoformat()),  # starts after it ends
        ]
        for scope in bad_scopes:
            with self.subTest(scope=scope):
                self.write_scope(scope)
                self.assert_load_fails("SCOPE_MALFORMED")


class TimeWindowTests(ScopeFixture):
    def test_scope_that_has_expired(self):
        guard = self.guard(clock=lambda: NOW + timedelta(days=31))
        self.assert_refused(guard, "192.168.56.5", "SCOPE_EXPIRED")

    def test_scope_that_is_not_valid_yet(self):
        guard = self.guard(clock=lambda: NOW - timedelta(days=2))
        self.assert_refused(guard, "192.168.56.5", "SCOPE_NOT_YET_VALID")

    def test_both_ends_of_the_window_are_inclusive(self):
        scope = make_scope()
        start = datetime.fromisoformat(scope["not_before"])
        end = datetime.fromisoformat(scope["not_after"])
        for moment in (start, end):
            with self.subTest(moment=moment):
                self.assertTrue(self.guard(scope, clock=lambda m=moment: m).authorise("192.168.56.5"))
        self.assert_refused(self.guard(scope, clock=lambda: end + timedelta(seconds=1)),
                            "192.168.56.5", "SCOPE_EXPIRED")

    def test_scope_that_expires_while_the_app_is_open(self):
        clock = {"now": NOW}
        guard = self.guard(clock=lambda: clock["now"])
        self.assertTrue(guard.authorise("192.168.56.5"))
        clock["now"] = NOW + timedelta(days=60)
        self.assert_refused(guard, "192.168.56.5", "SCOPE_EXPIRED")


class AuditTests(ScopeFixture):
    def test_every_decision_is_recorded(self):
        guard = self.guard()
        guard.authorise("192.168.56.5")
        self.assert_refused(guard, "8.8.8.8", "OUT_OF_SCOPE")
        self.assert_refused(guard, "localhost", "INVALID_TARGET")
        self.assertEqual([(e["decision"], e["code"]) for e in guard.audit],
                         [("ALLOWED", "IN_SCOPE"), ("REFUSED", "OUT_OF_SCOPE"),
                          ("REFUSED", "INVALID_TARGET")])

    def test_decisions_are_written_to_a_file_as_json_lines(self):
        log = os.path.join(self.folder.name, "logs", "audit.log")
        guard = self.guard(audit_path=log)
        guard.authorise("192.168.56.5")
        self.assert_refused(guard, "8.8.8.8", "OUT_OF_SCOPE")
        with open(log, encoding="utf-8") as handle:
            lines = [json.loads(line) for line in handle]
        self.assertEqual([line["target"] for line in lines], ["192.168.56.5", "8.8.8.8"])
        self.assertEqual(lines[1]["organisation"], "Demo SME Ltd")

    def test_a_log_that_cannot_be_written_does_not_break_a_refusal(self):
        blocker = os.path.join(self.folder.name, "blocker")
        open(blocker, "w").close()  # a file, so a folder cannot be made inside it
        guard = self.guard(audit_path=os.path.join(blocker, "audit.log"))
        self.assert_refused(guard, "8.8.8.8", "OUT_OF_SCOPE")

    def test_very_long_targets_are_shortened_in_the_log(self):
        guard = self.guard()
        self.assert_refused(guard, "x" * 5000, "INVALID_TARGET")
        self.assertEqual(len(guard.audit[0]["target"]), 200)

    def test_describe_summarises_the_scope(self):
        self.assertIn("Demo SME Ltd | 192.168.56.0/24 | valid until", self.guard().describe())


class ValidatedTargetTests(ScopeFixture):
    def test_cannot_be_created_directly(self):
        import ipaddress
        with self.assertRaises(TypeError):
            ValidatedTarget(ipaddress.ip_network("192.168.56.5"), object())

    def test_single_host_and_network_properties(self):
        guard = self.guard()
        host = guard.authorise("192.168.56.5")
        self.assertTrue(host.is_single_host)
        self.assertEqual((host.address, str(host)), ("192.168.56.5", "192.168.56.5"))
        network = guard.authorise("192.168.56.0/25")
        self.assertFalse(network.is_single_host)
        self.assertEqual(str(network), "192.168.56.0/25")


class EngineSpy:
    """Stands in for nmap.PortScanner and counts every use."""

    def __init__(self):
        self.created = 0
        self.scans = []

    def __call__(self):
        self.created += 1
        spy = self

        class Engine:
            def scan(self, hosts, ports, arguments):
                spy.scans.append((hosts, ports, arguments))

            def all_hosts(self):
                return []

        return Engine()


class ScannerEnforcementTests(ScopeFixture):
    """The scanner itself refuses: nmap is never even started."""

    def setUp(self):
        super().setUp()
        self.spy = EngineSpy()
        patcher = mock.patch.object(nmap, "PortScanner", self.spy)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_twenty_out_of_scope_attempts_never_start_the_engine(self):
        scanner = PortScanner(self.guard())
        for target in TWENTY_REFUSALS:
            with self.subTest(target=target):
                with self.assertRaises(ScopeError):
                    scanner.scan_target(target)
        self.assertEqual(len(TWENTY_REFUSALS), 20)
        self.assertEqual(self.spy.created, 0)
        self.assertEqual(self.spy.scans, [])
        self.assertEqual([e["decision"] for e in scanner.guard.audit], ["REFUSED"] * 20)

    def test_control_an_in_scope_target_does_start_the_engine(self):
        PortScanner(self.guard()).scan_target("192.168.56.102")
        self.assertEqual(self.spy.created, 1)
        self.assertEqual(self.spy.scans[0][0], "192.168.56.102")

    def test_a_target_the_guard_already_checked_is_not_checked_twice(self):
        guard = self.guard()
        PortScanner(guard).scan_target(guard.authorise("192.168.56.102"))
        self.assertEqual(self.spy.created, 1)
        self.assertEqual(len(guard.audit), 1)

    def test_a_whole_network_is_refused_for_now_without_starting_the_engine(self):
        with self.assertRaises(ValueError):
            PortScanner(self.guard()).scan_target("192.168.56.0/24")
        self.assertEqual(self.spy.created, 0)

    def test_an_expired_scope_blocks_the_scanner(self):
        scanner = PortScanner(self.guard(clock=lambda: NOW + timedelta(days=99)))
        with self.assertRaises(ScopeError):
            scanner.scan_target("192.168.56.102")
        self.assertEqual(self.spy.created, 0)

    def test_ipv6_targets_are_scanned_with_the_ipv6_flag(self):
        scanner = PortScanner(self.guard(make_scope(networks=["2001:db8:abcd::/48"])))
        scanner.scan_target("2001:db8:abcd::5")
        self.assertIn("-6", self.spy.scans[0][2])


if __name__ == "__main__":
    unittest.main()