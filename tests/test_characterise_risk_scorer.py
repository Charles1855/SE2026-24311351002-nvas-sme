"""
Characterisation tests for the AS-BUILT analysis/risk_scorer.py (v0.7-asbuilt behaviour).
They record what the code does today, not what it "should" do, so that later changes
(asset criticality) can be proven not to break existing behaviour.
"""
import pytest

from analysis.risk_scorer import RISK_ORDER, rank_findings, risk_label, score_to_level


def cve(cid, score, desc="d", sev="HIGH"):
    return {"cve_id": cid, "description": desc, "cvss_score": score, "severity": sev}


def svc(port, cves, product="prod", version="1.0", service="svc", match="CPE"):
    return {"port": port, "product": product, "version": version, "service": service,
            "cves": cves, "match_type": match}


# ---- score_to_level: boundary values from the assignment (3.9/4.0, 6.9/7.0, 8.9/9.0)
@pytest.mark.parametrize("score,level", [
    (None, "INFO"), (0.0, "LOW"), (3.9, "LOW"), (4.0, "MEDIUM"), (6.9, "MEDIUM"),
    (7.0, "HIGH"), (8.9, "HIGH"), (9.0, "CRITICAL"), (10.0, "CRITICAL"),
])
def test_score_to_level_boundaries(score, level):
    assert score_to_level(score) == level


def test_risk_order_is_most_severe_first():
    assert RISK_ORDER == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def test_info_is_labelled_no_match():
    assert risk_label("INFO") == "NO MATCH" and risk_label("HIGH") == "HIGH"


# ---- rank_findings
def test_rows_ordered_by_top_cvss_descending():
    rows = rank_findings([svc(21, [cve("A", 5.0)]), svc(22, [cve("B", 9.8)]), svc(80, [cve("C", 7.5)])])
    assert [r["port"] for r in rows] == [22, 80, 21]
    assert [r["rank"] for r in rows] == [1, 2, 3]


def test_tie_broken_by_more_cves_then_lower_port():
    rows = rank_findings([svc(80, [cve("A", 7.5)]), svc(22, [cve("B", 7.5), cve("C", 1.0)]),
                          svc(21, [cve("D", 7.5)])])
    assert [r["port"] for r in rows] == [22, 21, 80]


def test_services_without_cves_come_last_and_unranked():
    rows = rank_findings([svc(25, []), svc(22, [cve("A", 5.0)])])
    assert [r["port"] for r in rows] == [22, 25]
    assert rows[0]["rank"] == 1 and rows[1]["rank"] is None
    assert rows[1]["level"] == "INFO" and rows[1]["top_cvss"] is None


def test_cves_inside_a_row_sorted_by_score_then_id():
    rows = rank_findings([svc(22, [cve("CVE-2", 5.0), cve("CVE-1", 5.0), cve("CVE-3", 9.0)])])
    assert [c["cve_id"] for c in rows[0]["cves"]] == ["CVE-3", "CVE-1", "CVE-2"]


def test_row_level_follows_top_score():
    assert rank_findings([svc(22, [cve("A", 9.8)])])[0]["level"] == "CRITICAL"
    assert rank_findings([svc(22, [cve("A", 3.0)])])[0]["level"] == "LOW"


def test_all_scores_none_gives_info_but_still_ranked():
    row = rank_findings([svc(22, [cve("A", None, sev=None)])])[0]
    assert row["top_cvss"] is None and row["level"] == "INFO" and row["rank"] == 1


def test_product_falls_back_to_service_then_unknown():
    assert rank_findings([svc(1, [], product="")])[0]["product"] == "svc"
    assert rank_findings([svc(1, [], product="", service="")])[0]["product"] == "unknown"


def test_match_type_is_passed_through():
    assert rank_findings([svc(22, [cve("A", 5.0)], match="Name only")])[0]["match"] == "Name only"


def test_same_input_gives_same_output():
    data = [svc(80, [cve("A", 7.5)]), svc(22, [cve("B", 7.5)]), svc(21, [cve("C", 9.0)])]
    assert rank_findings(data) == rank_findings(list(reversed(data)))
