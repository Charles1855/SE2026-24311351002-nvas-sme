import json

import pytest

from analysis.delta import compute_delta, delta_from_db, render_markdown, write_report
from analysis.prioritiser import prioritise
from database import findings_store

H1, H2 = "192.168.56.101", "192.168.56.102"


def row(host=H1, port=21, cve="CVE-2011-2523", cvss=9.8, version="vsftpd 2.3.4"):
    return {"host": host, "port": port, "cve_id": cve, "cvss": cvss,
            "service": "svc", "version": version}


@pytest.fixture
def conn():
    return findings_store.connect(":memory:")


def save(conn, scan_id, rows, hosts):
    return findings_store.save_scan(conn, scan_id, prioritise(rows), hosts)


def fps(items):
    return {i["cve_id"] for i in items}


# ---- classification -----------------------------------------------------------
def test_new_fixed_persisting_classified(conn):
    save(conn, 1, [row(cve="CVE-A"), row(cve="CVE-B")], [H1])
    save(conn, 2, [row(cve="CVE-B"), row(cve="CVE-C")], [H1])
    d = delta_from_db(conn, 1, 2)
    assert fps(d["new"]) == {"CVE-C"}
    assert fps(d["fixed"]) == {"CVE-A"}
    assert fps(d["persisting"]) == {"CVE-B"}
    assert d["summary"] == {"new": 1, "fixed": 1, "persisting": 1}


def test_identical_rescan_has_only_persisting(conn):
    rows = [row(cve="CVE-A"), row(cve="CVE-B")]
    save(conn, 1, rows, [H1])
    save(conn, 2, rows, [H1])
    d = delta_from_db(conn, 1, 2)
    assert d["summary"] == {"new": 0, "fixed": 0, "persisting": 2}


def test_everything_fixed_when_host_clean_on_rescan(conn):
    save(conn, 1, [row(cve="CVE-A")], [H1])
    save(conn, 2, [], [H1])
    d = delta_from_db(conn, 1, 2)
    assert d["summary"]["fixed"] == 1


def test_host_not_rescanned_is_not_reported_fixed(conn):
    save(conn, 1, [row(H1, cve="CVE-A"), row(H2, cve="CVE-B")], [H1, H2])
    save(conn, 2, [row(H1, cve="CVE-A")], [H1])
    d = delta_from_db(conn, 1, 2)
    assert d["summary"]["fixed"] == 0
    assert d["hosts_not_rescanned"] == [H2]


def test_new_host_findings_count_as_new(conn):
    save(conn, 1, [row(H1, cve="CVE-A")], [H1])
    save(conn, 2, [row(H1, cve="CVE-A"), row(H2, cve="CVE-B")], [H1, H2])
    d = delta_from_db(conn, 1, 2)
    assert fps(d["new"]) == {"CVE-B"} and d["hosts_added"] == [H2]


def test_same_cve_other_port_is_a_different_finding(conn):
    save(conn, 1, [row(port=21, cve="CVE-A")], [H1])
    save(conn, 2, [row(port=2121, cve="CVE-A")], [H1])
    d = delta_from_db(conn, 1, 2)
    assert d["summary"] == {"new": 1, "fixed": 1, "persisting": 0}


# ---- evidence hashes -----------------------------------------------------------
def test_every_entry_has_64_char_evidence_hash(conn):
    save(conn, 1, [row(cve="CVE-A"), row(cve="CVE-B")], [H1])
    save(conn, 2, [row(cve="CVE-B"), row(cve="CVE-C")], [H1])
    d = delta_from_db(conn, 1, 2)
    for group in ("new", "fixed", "persisting"):
        for e in d[group]:
            assert len(e["evidence_hash"]) == 64


def test_unchanged_persisting_keeps_same_hash(conn):
    save(conn, 1, [row()], [H1])
    save(conn, 2, [row()], [H1])
    e = delta_from_db(conn, 1, 2)["persisting"][0]
    assert e["evidence_changed"] is False
    assert e["evidence_hash"] == e["previous_evidence_hash"]


def test_changed_evidence_is_flagged(conn):
    save(conn, 1, [row(version="MySQL 5.0.51a")], [H1])
    save(conn, 2, [row(version="MySQL 5.0.95")], [H1])
    e = delta_from_db(conn, 1, 2)["persisting"][0]
    assert e["evidence_changed"] is True
    assert e["evidence_hash"] != e["previous_evidence_hash"]


def test_delta_is_reproducible(conn):
    save(conn, 1, [row(cve="CVE-A"), row(cve="CVE-B")], [H1])
    save(conn, 2, [row(cve="CVE-B"), row(cve="CVE-C")], [H1])
    a = delta_from_db(conn, 1, 2)
    b = delta_from_db(conn, 1, 2)
    a.pop("generated_at"); b.pop("generated_at")
    assert a == b


# ---- de-duplication on rescans ---------------------------------------------------
def test_rescan_does_not_create_duplicate_registry_rows(conn):
    for scan_id in (1, 2, 3):
        save(conn, scan_id, [row(cve="CVE-A")], [H1])
    rows = findings_store.open_findings(conn)
    assert len(rows) == 1 and rows[0]["times_seen"] == 3
    assert rows[0]["first_seen_scan"] == 1 and rows[0]["last_seen_scan"] == 3


def test_saving_same_scan_twice_is_idempotent(conn):
    save(conn, 1, [row(cve="CVE-A")], [H1])
    again = save(conn, 1, [row(cve="CVE-A")], [H1])
    assert again["saved"] == 0
    assert findings_store.open_findings(conn)[0]["times_seen"] == 1


def test_fixed_finding_leaves_open_list(conn):
    save(conn, 1, [row(cve="CVE-A")], [H1])
    save(conn, 2, [], [H1])
    assert findings_store.open_findings(conn) == []


def test_reappearing_finding_reopens(conn):
    save(conn, 1, [row(cve="CVE-A")], [H1])
    save(conn, 2, [], [H1])
    save(conn, 3, [row(cve="CVE-A")], [H1])
    r = findings_store.open_findings(conn)[0]
    assert r["status"] == "open" and r["first_seen_scan"] == 1 and r["times_seen"] == 2


def test_unscanned_host_stays_open_in_registry(conn):
    save(conn, 1, [row(H2, cve="CVE-B")], [H2])
    save(conn, 2, [], [H1])      # scan 2 only covered H1
    assert len(findings_store.open_findings(conn)) == 1


# ---- error handling and output -------------------------------------------------------
def test_delta_for_unknown_scan_raises(conn):
    save(conn, 1, [row()], [H1])
    with pytest.raises(ValueError):
        delta_from_db(conn, 1, 99)


def test_compute_delta_works_without_database():
    old = [dict(fingerprint="a", host=H1, port=1, protocol="tcp", cve_id="CVE-A", cvss=5.0,
                risk_score=5.0, band="MEDIUM", evidence_hash="h" * 64)]
    d = compute_delta(old, [], [H1], [H1], 1, 2, generated_at="2026-11-24T00:00:00+00:00")
    assert d["summary"]["fixed"] == 1


def test_markdown_contains_sections_and_hash_prefix(conn):
    save(conn, 1, [row(cve="CVE-A")], [H1])
    save(conn, 2, [row(cve="CVE-B")], [H1])
    d = delta_from_db(conn, 1, 2)
    md = render_markdown(d)
    assert "New findings (1)" in md and "Fixed findings (1)" in md and "Persisting findings (0)" in md
    assert d["new"][0]["evidence_hash"][:16] in md


def test_write_report_creates_json_and_markdown(conn, tmp_path):
    save(conn, 1, [row(cve="CVE-A")], [H1])
    save(conn, 2, [row(cve="CVE-A")], [H1])
    jp, mp = write_report(delta_from_db(conn, 1, 2), tmp_path)
    assert jp.exists() and mp.exists()
    assert json.loads(jp.read_text(encoding="utf-8"))["summary"]["persisting"] == 1
