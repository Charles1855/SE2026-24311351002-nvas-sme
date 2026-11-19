from database.db import get_all_findings

RISK_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


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


def _service_row(entry):
    """One service's CVEs sorted by score (then CVE ID), plus its top score and risk level."""
    cves = sorted(
        entry["cves"],
        key=lambda c: (-(c["cvss_score"] or 0), c["cve_id"]),
    )
    scores = [c["cvss_score"] for c in cves if c["cvss_score"] is not None]
    top = max(scores) if scores else None
    return {
        "port": entry["port"],
        "product": entry["product"] or entry["service"] or "unknown",
        "version": entry["version"],
        "cves": cves,
        "top_cvss": top,
        "level": score_to_level(top),
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


def rank_findings(matched):
    """
    Turn the matcher's output into one ranked row per service.

    The results screen and the PDF report both call this, so they always agree.

    Order: highest CVSS score first, then more CVEs, then lower port number.
    Services with no CVEs come last. Inside a row the CVEs are sorted by score
    and then by CVE ID, so the same input always gives the same order.
    """
    rows = [_service_row(entry) for entry in matched]
    rows.sort(key=lambda r: (r["top_cvss"] is None, -(r["top_cvss"] or 0),
                             -len(r["cves"]), r["port"]))
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