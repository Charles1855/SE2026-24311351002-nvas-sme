"""
Standalone tests for the ranking and the PDF report.

Run from the project root:
    python -m unittest test_report_generator -v
"""
import os
import random
import tempfile
import unittest
from datetime import datetime

from analysis.report_generator import (
    clean,
    default_filename,
    fingerprint,
    format_duration,
    generate_report,
)
from analysis.risk_scorer import rank_findings


def cve(cve_id, score, severity="HIGH", description="A known flaw."):
    return {"cve_id": cve_id, "description": description,
            "cvss_score": score, "severity": severity}


def entry(port, product, version="", cves=(), match_type=""):
    return {"port": port, "service": "svc", "product": product, "version": version,
            "cves": list(cves), "match_type": match_type}


SAMPLE = [
    entry(21, "vsftpd", "2.3.4", [cve("CVE-2011-2523", 9.8, "CRITICAL")], "Keyword + version"),
    entry(22, "OpenSSH", "4.7p1", [cve("CVE-2008-1657", 6.5, "MEDIUM"),
                                   cve("CVE-2008-5161", 2.6, "LOW")], "Keyword + version"),
    entry(53, "ISC BIND", "9.4.2", [cve("CVE-2008-4163", 7.8),
                                    cve("CVE-2008-0122", 10.0, "CRITICAL")], "CPE"),
    entry(80, "Apache httpd", "2.2.8", [cve("CVE-2010-0001", 9.8, "CRITICAL"),
                                        cve("CVE-2010-0002", 5.0, "MEDIUM")], "CPE"),
    entry(139, "Samba smbd", "3.X - 4.X"),
    entry(3306, "MySQL", "5.0.51a-3ubuntu5"),
    entry(5900, "VNC", "", [cve("CVE-2002-2088", 10.0)], "Name only"),
]


class RankFindingsTests(unittest.TestCase):
    def test_highest_score_first_then_more_cves_then_port(self):
        rows = rank_findings(SAMPLE)
        self.assertEqual([r["port"] for r in rows], [53, 5900, 80, 21, 22, 139, 3306])

    def test_services_without_cves_come_last_and_are_unranked(self):
        rows = rank_findings(SAMPLE)
        self.assertEqual([r["rank"] for r in rows], [1, 2, 3, 4, 5, None, None])

    def test_cves_inside_a_row_are_sorted_by_score(self):
        bind = rank_findings(SAMPLE)[0]
        self.assertEqual([c["cve_id"] for c in bind["cves"]],
                         ["CVE-2008-0122", "CVE-2008-4163"])

    def test_equal_scores_are_ordered_by_cve_id(self):
        row = rank_findings([entry(1, "x", "1", [cve("CVE-2020-0002", 5.0),
                                                 cve("CVE-2020-0001", 5.0)])])[0]
        self.assertEqual([c["cve_id"] for c in row["cves"]], ["CVE-2020-0001", "CVE-2020-0002"])

    def test_input_order_does_not_change_the_ranking(self):
        expected = [r["port"] for r in rank_findings(SAMPLE)]
        for seed in range(5):
            shuffled = SAMPLE[:]
            random.Random(seed).shuffle(shuffled)
            self.assertEqual([r["port"] for r in rank_findings(shuffled)], expected)

    def test_risk_level_follows_the_top_score(self):
        levels = {r["port"]: r["level"] for r in rank_findings(SAMPLE)}
        self.assertEqual(levels[53], "CRITICAL")
        self.assertEqual(levels[22], "MEDIUM")
        self.assertEqual(levels[139], "INFO")

    def test_missing_match_type_is_allowed(self):
        raw = {"port": 9, "service": "x", "product": "p", "version": "1", "cves": []}
        self.assertEqual(rank_findings([raw])[0]["match"], "")


class FingerprintTests(unittest.TestCase):
    def test_is_a_sha256_hex_string(self):
        value = fingerprint(rank_findings(SAMPLE))
        self.assertEqual(len(value), 64)
        int(value, 16)

    def test_same_findings_give_the_same_value_in_any_input_order(self):
        shuffled = SAMPLE[:]
        random.Random(1).shuffle(shuffled)
        self.assertEqual(fingerprint(rank_findings(SAMPLE)), fingerprint(rank_findings(shuffled)))

    def test_changing_a_score_changes_the_value(self):
        changed = [dict(e, cves=[dict(c) for c in e["cves"]]) for e in SAMPLE]
        changed[0]["cves"][0]["cvss_score"] = 9.7
        self.assertNotEqual(fingerprint(rank_findings(SAMPLE)), fingerprint(rank_findings(changed)))


class HelperTests(unittest.TestCase):
    def test_clean_replaces_smart_punctuation(self):
        self.assertEqual(clean("\u201cquoted\u201d \u2013 it\u2019s\u2026"), '"quoted" - it\'s...')

    def test_clean_replaces_characters_the_pdf_font_cannot_draw(self):
        self.assertEqual(clean("caf\u00e9 \u4e2d"), "caf\u00e9 ?")

    def test_clean_handles_none_and_newlines(self):
        self.assertEqual(clean(None), "")
        self.assertEqual(clean("a\r\nb\rc"), "a\nb\nc")

    def test_default_filename_is_safe_and_dated(self):
        when = datetime(2026, 11, 5, 9, 30)
        self.assertEqual(default_filename("192.168.56.101", when),
                         "NVAS_report_192.168.56.101_20261105_0930.pdf")
        self.assertNotIn(":", default_filename("fe80::1", when))

    def test_format_duration(self):
        self.assertEqual(format_duration(None), "unknown")
        self.assertEqual(format_duration(45), "45 s")
        self.assertEqual(format_duration(125), "2 min 5 s")


class GenerateReportTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.folder.name, "report.pdf")

    def tearDown(self):
        self.folder.cleanup()

    def make(self, matched, **kwargs):
        return generate_report("192.168.56.101", matched, output_path=self.path, **kwargs)

    def assert_valid_pdf(self):
        with open(self.path, "rb") as handle:
            data = handle.read()
        self.assertTrue(data.startswith(b"%PDF"))
        self.assertIn(b"%%EOF", data[-1024:])
        self.assertGreater(len(data), 2000)

    def test_creates_a_pdf_and_returns_its_path(self):
        returned = self.make(SAMPLE, info={"seconds": 72, "finished": datetime(2026, 11, 5, 9, 30)})
        self.assertEqual(returned, self.path)
        self.assert_valid_pdf()

    def test_creates_missing_folders(self):
        nested = os.path.join(self.folder.name, "a", "b", "r.pdf")
        generate_report("10.0.0.1", SAMPLE, output_path=nested)
        self.assertTrue(os.path.exists(nested))

    def test_empty_scan_still_makes_a_report(self):
        self.make([])
        self.assert_valid_pdf()

    def test_only_unmatched_services(self):
        self.make([entry(139, "Samba smbd", "3.X - 4.X"), entry(445, "Samba smbd", "3.X - 4.X")])
        self.assert_valid_pdf()

    def test_text_the_pdf_font_cannot_draw_does_not_crash(self):
        text = "Smart \u201cquotes\u201d, a dash \u2013 and \u4e2d\u6587 characters " * 20
        self.make([entry(80, "Web \u4e2d", "1.0", [cve("CVE-2020-0001", 7.5, "HIGH", text)])])
        self.assert_valid_pdf()

    def test_many_services_run_over_several_pages(self):
        many = [entry(1000 + i, f"Service number {i} with a long name " * 3, "1.2.3-ubuntu" * 4,
                      [cve(f"CVE-2020-{i:04d}", 5.0 + (i % 5), "MEDIUM", "Long description. " * 40)
                       for _ in range(3)])
                for i in range(120)]
        self.make(many)
        self.assert_valid_pdf()

    def test_unscored_cve_and_missing_severity_are_handled(self):
        self.make([entry(25, "Postfix", "", [cve("CVE-2024-0001", None, None)], "Name only")])
        self.assert_valid_pdf()


if __name__ == "__main__":
    unittest.main()