import pytest

from analysis.scan_integration import matched_to_rows, record_scan
from database import findings_store

T, OTHER = "192.168.56.102", "192.168.56.50"


def cve(cid, score=9.8):
    return {"cve_id": cid, "description": "d", "cvss_score": score, "severity": "HIGH"}


def entry(port, cves, product="vsftpd", version="2.3.4"):
    return {"port": port, "service": "ftp", "product": product, "version": version,
            "cves": cves, "match_type": "keyword"}


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "test.db")


def run(matched, target=T, db_path=None, tmp=None):
    return record_scan(matched, target, db_path=db_path, write_reports=False)


# ---- flattening ---------------------------------------------------------------
def test_flatten_gives_one_row_per_cve():
    rows = matched_to_rows([entry(21, [cve("CVE-1"), cve("CVE-2")])], T)
    assert [r["cve_id"] for r in rows] == ["CVE-1", "CVE-2"]
    assert all(r["host"] == T and r["port"] == 21 for r in rows)


def test_service_without_cves_gives_no_rows():
    assert matched_to_rows([entry(25, [])], T) == []


def test_missing_score_becomes_zero():
    assert matched_to_rows([entry(21, [cve("CVE-1", None)])], T)[0]["cvss"] == 0.0


def test_product_preferred_over_service_name():
    row = matched_to_rows([entry(21, [cve("CVE-1")], product="vsftpd")], T)[0]
    assert row["service"] == "vsftpd"


def test_entry_host_overrides_target():
    e = entry(21, [cve("CVE-1")])
    e["host"] = OTHER
    assert matched_to_rows([e], T)[0]["host"] == OTHER


# ---- recording scans ------------------------------------------------------------
def test_first_scan_has_no_delta(db):
    r = run([entry(21, [cve("CVE-1")])], db_path=db)
    assert r["previous_run_id"] is None and r["delta"] is None
    assert len(r["findings"]) == 1 and r["findings"][0].rank == 1


def test_second_scan_produces_delta(db):
    run([entry(21, [cve("CVE-A")]), entry(80, [cve("CVE-B", 7.5)])], db_path=db)
    r = run([entry(80, [cve("CVE-B", 7.5)]), entry(22, [cve("CVE-C", 5.0)])], db_path=db)
    d = r["delta"]
    assert {e["cve_id"] for e in d["new"]} == {"CVE-C"}
    assert {e["cve_id"] for e in d["fixed"]} == {"CVE-A"}
    assert {e["cve_id"] for e in d["persisting"]} == {"CVE-B"}


def test_identical_rescan_is_all_persisting_and_deduplicated(db):
    matched = [entry(21, [cve("CVE-A")]), entry(80, [cve("CVE-B")])]
    run(matched, db_path=db)
    r = run(matched, db_path=db)
    assert r["delta"]["summary"] == {"new": 0, "fixed": 0, "persisting": 2}
    conn = findings_store.connect(db)
    rows = findings_store.open_findings(conn)
    conn.close()
    assert len(rows) == 2 and all(x["times_seen"] == 2 for x in rows)


def test_different_targets_are_not_compared(db):
    run([entry(21, [cve("CVE-A")])], target=T, db_path=db)
    r = run([entry(21, [cve("CVE-A")])], target=OTHER, db_path=db)
    assert r["previous_run_id"] is None and r["delta"] is None


def test_duplicate_cve_in_matcher_output_collapses(db):
    r = run([entry(21, [cve("CVE-A"), cve("CVE-A")])], db_path=db)
    assert len(r["findings"]) == 1


def test_scan_with_no_cves_still_records_run_and_marks_fixed(db):
    run([entry(21, [cve("CVE-A")])], db_path=db)
    r = run([entry(21, [])], db_path=db)
    assert r["delta"]["summary"]["fixed"] == 1


def test_last_two_runs(db):
    conn = findings_store.connect(db)
    assert findings_store.last_two_runs(conn, T) is None
    a = findings_store.new_run(conn, T)
    assert findings_store.last_two_runs(conn, T) is None
    b = findings_store.new_run(conn, T)
    findings_store.new_run(conn, OTHER)
    assert findings_store.last_two_runs(conn, T) == (a, b)
    conn.close()


def test_reports_written_when_enabled(db, tmp_path):
    record_scan([entry(21, [cve("CVE-A")])], T, db_path=db, report_dir=str(tmp_path))
    record_scan([entry(21, [cve("CVE-A")])], T, db_path=db, report_dir=str(tmp_path))
    assert len(list(tmp_path.glob("delta_scan*_to_scan*.md"))) == 1


# ---- CVSS version from the matcher and report path -----------------------------------
def test_matcher_cvss_version_reaches_findings(db):
    c = cve("CVE-V2", 5.0)
    c["cvss_version"] = "2.0"
    r = run([entry(21, [c, cve("CVE-V31", 7.5) | {"cvss_version": "3.1"}])], db_path=db)
    basis = {f.cve_id: f.score_basis for f in r["findings"]}
    assert basis["CVE-V2"] == "CVSS v2.0 (fallback)" and basis["CVE-V31"] == "CVSS v3.1"


def test_version_change_between_scans_marks_evidence_changed(db):
    a = cve("CVE-A", 5.0) | {"cvss_version": "2.0"}
    b = cve("CVE-A", 5.0) | {"cvss_version": "3.1"}
    run([entry(21, [a])], db_path=db)
    d = run([entry(21, [b])], db_path=db)["delta"]
    assert d["persisting"][0]["evidence_changed"] is True


def test_report_paths_returned_on_second_scan(db, tmp_path):
    first = record_scan([entry(21, [cve("CVE-A")])], T, db_path=db, report_dir=str(tmp_path))
    second = record_scan([entry(21, [cve("CVE-A")])], T, db_path=db, report_dir=str(tmp_path))
    assert first["report_paths"] is None
    json_path, md_path = second["report_paths"]
    assert json_path.exists() and md_path.exists()
