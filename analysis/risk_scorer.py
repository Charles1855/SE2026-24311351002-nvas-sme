from database.db import get_all_findings

def score_to_levels(score):
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
                "cve_count":0,
                "max_cvss":0.0,
                "driving_cve": None
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
            "risk_level": score_to_levels(score)
        })
    
    results.sort(key=lambda r: r["max_cvss"], reverse=True)
    return results

