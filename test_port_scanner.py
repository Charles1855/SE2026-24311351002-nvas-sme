"""
Tests for how the scanner turns nmap's answer into a list of open ports.

Run from the project root:
    python -m unittest test_port_scanner -v
"""
import unittest
from unittest import mock

import nmap

from scanner.port_scanner import PortScanner

ADDRESS = "192.168.56.102"


class FakeHost(dict):
    def all_protocols(self):
        return list(self.keys())


class FakeEngine:
    """Looks like nmap.PortScanner after a scan, with ports we choose."""

    def __init__(self, ports=None, up=True):
        self.ports = ports or {}
        self.up = up
        self.scan_calls = []

    def scan(self, hosts, ports, arguments):
        self.scan_calls.append((hosts, ports, arguments))

    def all_hosts(self):
        return [ADDRESS] if self.up else []

    def __getitem__(self, address):
        return FakeHost({"tcp": self.ports})


class AllowAll:
    """A guard stand-in: these tests are about parsing, not about scope."""

    def authorise(self, target):
        from scanner.scope_guard import ValidatedTarget, _TOKEN
        import ipaddress
        return ValidatedTarget(ipaddress.ip_network(target), _TOKEN)


def scan(engine, port_range="1-10000"):
    with mock.patch.object(nmap, "PortScanner", lambda: engine):
        return PortScanner(AllowAll()).scan_target(ADDRESS, port_range)


class CollectOpenPortsTests(unittest.TestCase):
    def test_only_open_ports_are_returned_in_port_order(self):
        engine = FakeEngine({
            80: {"state": "open", "name": "http", "product": "Apache httpd",
                 "version": "2.2.8", "cpe": "cpe:/a:apache:http_server:2.2.8"},
            22: {"state": "open", "name": "ssh", "product": "OpenSSH", "version": "4.7p1"},
            23: {"state": "closed", "name": "telnet"},
            25: {"state": "filtered", "name": "smtp"},
        })
        results = scan(engine)
        self.assertEqual([r["port"] for r in results], [22, 80])
        self.assertEqual(results[1]["cpe"], "cpe:/a:apache:http_server:2.2.8")

    def test_every_result_has_the_fields_the_matcher_needs(self):
        results = scan(FakeEngine({21: {"state": "open", "name": "ftp"}}))
        self.assertEqual(sorted(results[0]),
                         ["cpe", "port", "product", "protocol", "service", "state", "version"])

    def test_missing_details_get_safe_defaults(self):
        row = scan(FakeEngine({9: {"state": "open"}}))[0]
        self.assertEqual((row["service"], row["product"], row["version"], row["cpe"]),
                         ("unknown", "", "", ""))

    def test_a_host_that_is_down_gives_an_empty_list(self):
        self.assertEqual(scan(FakeEngine(up=False)), [])

    def test_a_host_with_no_open_ports_gives_an_empty_list(self):
        self.assertEqual(scan(FakeEngine({80: {"state": "closed"}})), [])


class ScanArgumentsTests(unittest.TestCase):
    def test_nmap_is_given_the_address_the_ports_and_version_detection(self):
        engine = FakeEngine()
        scan(engine, "1-500")
        hosts, ports, arguments = engine.scan_calls[0]
        self.assertEqual((hosts, ports), (ADDRESS, "1-500"))
        self.assertIn("-sV", arguments)


if __name__ == "__main__":
    unittest.main()