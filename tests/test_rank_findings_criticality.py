"""Asset criticality in rank_findings, and CVSS version passing through the NVD parser."""
from analysis.risk_scorer import rank_findings
from analysis.vuln_matcher import _parse

T, OTHER = "192.168.56.102", "192.168.56.50"


def cve(cid, score):
    return {"cve_id": cid, "description": "d", "cvss_score": score, "severity": "HIGH"}


def svc(port, cves):
    return {"port": port, "product": "p", "version": "1", "service": "s",
            "cves": cves, "match_type": "CPE"}


def test_no_target_means_plain_cvss_behaviour():
    row = rank_findings([svc(22, [cve("A", 7.5)])])[0]
    assert row["risk_score"] == 7.5 and row["criticality"] == 3 and row["level"] == "HIGH"


def test_high_criticality_raises_level():
    # 7.5 x 1.2 = 9.0 -> CRITICAL on a criticality-5 asset
    row = rank_findings([svc(22, [cve("A", 7.5)])], T, {"default": 3, T: 5})[0]
    assert row["risk_score"] == 9.0 and row["level"] == "CRITICAL"


def test_low_criticality_lowers_level():
    # 9.8 x 0.8 = 7.84 -> HIGH on a criticality-1 asset
    row = rank_findings([svc(22, [cve("A", 9.8)])], OTHER, {"default": 3, OTHER: 1})[0]
    assert row["risk_score"] == 7.84 and row["level"] == "HIGH"


def test_unlisted_host_uses_default_criticality():
    row = rank_findings([svc(22, [cve("A", 5.0)])], "10.0.0.9", {"default": 3, T: 5})[0]
    assert row["criticality"] == 3 and row["risk_score"] == 5.0


def test_top_cvss_stays_the_raw_score():
    row = rank_findings([svc(22, [cve("A", 5.0)])], T, {"default": 3, T: 5})[0]
    assert row["top_cvss"] == 5.0 and row["risk_score"] == 6.0


def test_risk_score_capped_at_ten():
    assert rank_findings([svc(22, [cve("A", 9.8)])], T, {T: 5})[0]["risk_score"] == 10.0


def test_ranking_still_deterministic_with_criticality():
    data = [svc(80, [cve("A", 9.8)]), svc(22, [cve("B", 9.8)]), svc(21, [cve("C", 7.0)])]
    table = {"default": 3, T: 5}
    a = rank_findings(data, T, table)
    b = rank_findings(list(reversed(data)), T, table)
    assert a == b and [r["port"] for r in a] == [22, 80, 21]


def test_missing_config_file_falls_back_to_default(monkeypatch, tmp_path):
    import analysis.risk_scorer as rs
    monkeypatch.setattr(rs, "CRITICALITY_PATH", tmp_path / "missing.json")
    assert rank_findings([svc(22, [cve("A", 7.5)])], T)[0]["criticality"] == 3


# ---- NVD parser keeps the CVSS version -------------------------------------------
def nvd(metrics):
    return {"vulnerabilities": [{"cve": {"id": "CVE-1", "metrics": metrics,
            "descriptions": [{"lang": "en", "value": "x"}]}}]}


def test_parse_reports_v31():
    m = {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}
    assert _parse(nvd(m), 5)[0]["cvss_version"] == "3.1"


def test_parse_prefers_v31_over_v2():
    m = {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}],
         "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]}
    result = _parse(nvd(m), 5)[0]
    assert result["cvss_version"] == "3.1" and result["cvss_score"] == 7.5


def test_parse_flags_v2_fallback():
    m = {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}]}
    result = _parse(nvd(m), 5)[0]
    assert result["cvss_version"] == "2.0" and result["severity"] == "MEDIUM"


def test_parse_without_metrics_has_no_version():
    result = _parse(nvd({}), 5)[0]
    assert result["cvss_score"] is None and result["cvss_version"] is None
