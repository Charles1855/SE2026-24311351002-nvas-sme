import requests
import time

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = "4BFEAE57-B0E7-4D5F-93C5-5F1F57CB514A"

def search_cves(product, version, max_results=5):
    query = f"{product} {version}".strip()
    params = {"keywordSearch": query, "resultsPerPage": max_results}
    headers = {"apiKey": API_KEY} if API_KEY else{}

    response = requests.get(NVD_API_URL, params=params, headers=headers)
    response.raise_for_status()
    data = response.json()

    matches = []
    for items in data.get("vulnerabilities",[]):
        cve = items.get("cve")
        metrics = cve.get("metrics",{})
        score, severity = None, None
        if "cvssMetricV31" in metrics:
            score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
        elif "cvssMetricV2" in metrics:
            score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
        
        matches.append({
            "cve_id": cve["id"],
            "description": cve["descriptions"][0]["value"],
            "cvss_score": score,
            "severity": severity
        })
    return matches

def match_scan_results(scan_results):
    matched=[]
    for entry in scan_results:
        if not entry["product"]:
            continue #skip ports nmap couldn't identify
        print(f"[*]Searching NVD for: {entry['product']} {entry['version']}")
        cves = search_cves(entry["product"],entry["version"])
        matched.append({**entry,"cves": cves})
        time.sleep(0.6 if API_KEY != "4BFEAE57-B0E7-4D5F-93C5-5F1F57CB514A" else 6)
    return matched
        
            
        
        
    
    
    
    