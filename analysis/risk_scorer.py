from pathlib import Path

from analysis.prioritiser import (
    DEFAULT_CRITICALITY, criticality_for, load_criticality, score_finding,
)
from database.db import get_all_findings

RISK_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
CRITICALITY_PATH = Path(__file__).resolve().parent.parent / "config" / "asset_criticality.json"


def score_to_level(score):
    if score is None:
        return "INFO"
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"


def risk_label(level):
    """INFO means no CVE matched, which is not the same as 'safe'."""
    return "NO MATCH" if level == "INFO" else level


def _service_row(entry, criticality=DEFAULT_CRITICALITY):
    """
    One service's CVEs sorted by score (then CVE ID), plus its top score and risk level.
    The level comes from risk_score = top CVSS x asset criticality multiplier (capped at 10).
    With the default criticality (3) the multiplier is 1.0, so risk_score equals top_cvss.
    """
    cves = sorted(
        entry["cves"],
        key=lambda c: (-(c["cvss_score"] or 0), c["cve_id"]),
    )
    scores = [c["cvss_score"] for c in cves if c["cvss_score"] is not None]
    top = max(scores) if scores else None
    risk = score_finding(top, criticality)[1] if top is not None else None
    return {
        "port": entry["port"],
        "product": entry["product"] or entry["service"] or "unknown",
        "version": entry["version"],
        "cves": cves,
        "top_cvss": top,
        "risk_score": risk,
        "criticality": criticality,
        "level": score_to_level(risk),
        "match": entry.get("match_type", ""),
    }


def _number_rows(rows):
    """Rank 1, 2, 3... for services that have CVEs. Services without CVEs get None."""
    rank = 0
    for row in rows:
        if row["cves"]:
            rank += 1
            row["rank"] = rank
        else:
            row["rank"] = None


def rank_findings(matched, target=None, criticality_table=None):
    """
    Turn the matcher's output into one ranked row per service.

    The results screen and the PDF report both call this, so they always agree.

    Pass the scan target so the host's asset criticality (config/asset_criticality.json)
    is applied. Without a target the default criticality is used, which leaves the
    ranking identical to plain CVSS ordering.

    Order: highest risk score first, then higher CVSS, then more CVEs, then lower
    port number. Services with no CVEs come last. Inside a row the CVEs are sorted
    by score and then by CVE ID, so the same input always gives the same order.
    """
    criticality = DEFAULT_CRITICALITY
    if target:
        table = criticality_table if criticality_table is not None \
            else load_criticality(CRITICALITY_PATH)
        criticality = criticality_for(target, table)
    rows = [_service_row(entry, criticality) for entry in matched]
    rows.sort(key=lambda r: (r["risk_score"] is None, -(r["risk_score"] or 0),
                             -(r["top_cvss"] or 0), -len(r["cves"]), r["port"]))
    _number_rows(rows)
    return rows


def calculate_port_risk():
    rows = get_all_findings()

    ports = {}
    for target, port, product, version, cve_id, severity, cvss_score in rows:
        key = (target, port)

        if key not in ports:
            ports[key] = {
                "target": target,
                "port": port,
                "product": product,
                "version": version,
                "cve_count": 0,
                "max_cvss": 0.0,
                "driving_cve": None,
            }

        if cve_id is not None:
            ports[key]["cve_count"] += 1
            if cvss_score is not None and cvss_score > ports[key]["max_cvss"]:
                ports[key]["max_cvss"] = cvss_score
                ports[key]["driving_cve"] = cve_id

    results = []
    for data in ports.values():
        score = data["max_cvss"] if data["cve_count"] > 0 else None
        results.append({
            **data,
            "risk_level": score_to_level(score),
        })

    results.sort(key=lambda r: r["max_cvss"], reverse=True)
    return results