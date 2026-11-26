import random

import pytest

from analysis.prioritiser import (
    load_criticality, make_evidence_hash, make_fingerprint, normalise_finding,
    prioritise, score_finding, severity_band, validate_criticality,
)

H1, H2 = "192.168.56.101", "192.168.56.102"


def row(host=H1, port=21, cve="CVE-2011-2523", cvss=9.8, **extra):
    base = {"host": host, "port": port, "cve_id": cve, "cvss": cvss,
            "service": "ftp", "version": "vsftpd 2.3.4"}
    base.update(extra)
    return base


# ---- scoring formula -------------------------------------------------------
def test_default_criticality_keeps_cvss():
    assert score_finding(7.5, 3) == (7.5, 7.5)


def test_higher_criticality_raises_score():
    assert score_finding(5.0, 5)[0] > score_finding(5.0, 3)[0]


def test_lower_criticality_lowers_score():
    assert score_finding(5.0, 1)[0] < score_finding(5.0, 3)[0]


def test_risk_score_is_capped_at_ten():
    raw, capped = score_finding(9.8, 5)
    assert raw == 11.76 and capped == 10.0


@pytest.mark.parametrize("score,band", [
    (10.0, "CRITICAL"), (9.0, "CRITICAL"), (8.9, "HIGH"), (7.0, "HIGH"),
    (6.9, "MEDIUM"), (4.0, "MEDIUM"), (3.9, "LOW"), (0.1, "LOW"), (0.0, "INFO"),
])
def test_severity_bands(score, band):
    assert severity_band(score) == band


@pytest.mark.parametrize("bad", [0, 6, -1, "x", None])
def test_invalid_criticality_rejected(bad):
    with pytest.raises(ValueError):
        validate_criticality(bad)


def test_cvss_out_of_range_rejected():
    with pytest.raises(ValueError):
        normalise_finding(row(cvss=11))


# ---- reproducible ranking ---------------------------------------------------
def sample_rows():
    return [
        row(H1, 21, "CVE-2011-2523", 9.8),
        row(H1, 22, "CVE-2010-4478", 7.5),
        row(H1, 80, "CVE-2017-7679", 9.8),
        row(H2, 80, "CVE-2017-7679", 9.8),
        row(H2, 3306, "CVE-2012-2122", 5.9),
        row(H1, 25, "CVE-2010-4344", 7.5),
    ]


def test_ranking_is_same_for_any_input_order():
    table = {"default": 3, H2: 5}
    expected = [(f.fingerprint, f.rank) for f in prioritise(sample_rows(), table)]
    for seed in range(25):
        rows = sample_rows()
        random.Random(seed).shuffle(rows)
        assert [(f.fingerprint, f.rank) for f in prioritise(rows, table)] == expected


def test_ranking_is_same_across_repeated_runs():
    a = [f.to_dict() for f in prioritise(sample_rows())]
    b = [f.to_dict() for f in prioritise(sample_rows())]
    assert a == b


def test_ranks_are_consecutive_from_one():
    ranks = [f.rank for f in prioritise(sample_rows())]
    assert ranks == list(range(1, len(ranks) + 1))


def test_asset_criticality_changes_order():
    rows = [row(H1, 80, "CVE-A-1", 7.0), row(H2, 80, "CVE-B-1", 6.0)]
    plain = prioritise(rows, {"default": 3})
    assert plain[0].host == H1
    boosted = prioritise(rows, {"default": 3, H2: 5})   # 6.0*1.2=7.2 beats 7.0
    assert boosted[0].host == H2


def test_tie_break_is_deterministic_by_host_then_port():
    rows = [row(H2, 80, "CVE-X-1", 5.0), row(H1, 443, "CVE-X-2", 5.0), row(H1, 80, "CVE-X-3", 5.0)]
    order = [(f.host, f.port) for f in prioritise(rows)]
    assert order == [(H1, 80), (H1, 443), (H2, 80)]


def test_numeric_ip_order_not_string_order():
    rows = [row("192.168.56.100", 80, "CVE-X-1", 5.0), row("192.168.56.20", 80, "CVE-X-2", 5.0)]
    assert [f.host for f in prioritise(rows)] == ["192.168.56.20", "192.168.56.100"]


# ---- de-duplication ---------------------------------------------------------
def test_duplicate_cve_same_host_port_collapses():
    assert len(prioritise([row(), row()])) == 1


def test_same_cve_on_different_ports_is_not_duplicate():
    assert len(prioritise([row(port=21), row(port=2121)])) == 2


def test_same_cve_on_different_hosts_is_not_duplicate():
    assert len(prioritise([row(host=H1), row(host=H2)])) == 2


def test_duplicate_keeps_higher_cvss():
    result = prioritise([row(cvss=5.0), row(cvss=9.0)])
    assert len(result) == 1 and result[0].cvss == 9.0


def test_cve_case_and_whitespace_normalised():
    assert len(prioritise([row(cve="cve-2011-2523"), row(cve=" CVE-2011-2523 ")])) == 1


def test_rows_without_cve_are_skipped():
    assert prioritise([row(cve=None), {"host": H1, "port": 22, "cve_id": ""}]) == []


# ---- fingerprint and evidence hash -----------------------------------------
def test_fingerprint_is_stable():
    assert make_fingerprint(H1, 21, "tcp", "CVE-1") == make_fingerprint(H1, 21, "TCP", "cve-1")


def test_fingerprint_differs_per_port():
    assert make_fingerprint(H1, 21, "tcp", "CVE-1") != make_fingerprint(H1, 22, "tcp", "CVE-1")


def test_evidence_hash_is_64_hex():
    f = normalise_finding(row())
    assert len(f.evidence_hash) == 64 and int(f.evidence_hash, 16) >= 0


def test_evidence_hash_stable_for_same_evidence():
    assert normalise_finding(row()).evidence_hash == normalise_finding(row()).evidence_hash


def test_evidence_hash_changes_when_version_changes():
    a = normalise_finding(row(version="vsftpd 2.3.4"))
    b = normalise_finding(row(version="vsftpd 3.0.5"))
    assert a.evidence_hash != b.evidence_hash and a.fingerprint == b.fingerprint


def test_evidence_hash_changes_when_cvss_changes():
    assert normalise_finding(row(cvss=9.8)).evidence_hash != normalise_finding(row(cvss=7.5)).evidence_hash


# ---- input handling ----------------------------------------------------------
def test_alternative_key_names_accepted():
    f = normalise_finding({"ip": H1, "portid": "22", "cve": "CVE-1", "cvss_score": "7.5"})
    assert (f.host, f.port, f.cve_id, f.cvss) == (H1, 22, "CVE-1", 7.5)


def test_v2_score_is_flagged_as_fallback():
    f = normalise_finding(row(cvss_version="2.0"))
    assert "fallback" in f.score_basis


def test_v31_basis_is_default():
    assert normalise_finding(row()).score_basis == "CVSS v3.1"


def test_missing_host_rejected():
    with pytest.raises(ValueError):
        normalise_finding({"port": 1, "cve_id": "CVE-1", "cvss": 5})


def test_load_criticality_missing_file_gives_default(tmp_path):
    assert load_criticality(tmp_path / "nope.json") == {"default": 3}


def test_load_criticality_reads_and_validates(tmp_path):
    p = tmp_path / "c.json"
    p.write_text('{"192.168.56.102": 5}', encoding="utf-8")
    table = load_criticality(p)
    assert table["192.168.56.102"] == 5 and table["default"] == 3
    p.write_text('{"192.168.56.102": 9}', encoding="utf-8")
    with pytest.raises(ValueError):
        load_criticality(p)
