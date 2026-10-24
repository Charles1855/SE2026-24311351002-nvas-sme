import requests
import time

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = "4BFEAE57-B0E7-4D5F-93C5-5F1F57CB514A"

def search_cves(product, version, max_results=5, retries=3):
    query = f"{product} {version}".strip()
    params = {"keywordSearch": query, "resultsPerPage": max_results}
    headers = {"apiKey": API_KEY} if API_KEY else {}

    for attempt in range(retries):
        try:
            response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            break
        except requests.exceptions.RequestException as e:
            print(f"  [!] Request failed (attempt {attempt+1}/{retries}): {e}")
            if attempt < retries - 1:
                time.sleep(3)
            else:
                print(f"  [!] Giving up on {query} after {retries} attempts")
                return []

    matches = []
    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        metrics = cve.get("metrics", {})
        score, severity = None, None
        if "cvssMetricV31" in metrics:
            score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
        elif "cvssMetricV2" in metrics:
            v2 = metrics["cvssMetricV2"][0]
            score = v2["cvssData"]["baseScore"]
            severity = v2.get("baseSeverity")

        matches.append({
            "cve_id": cve["id"],
            "description": cve["descriptions"][0]["value"],
            "cvss_score": score,
            "severity": severity
        })
    return matches

def match_scan_results(scan_results, progress_callback=None):
    matched = []
    total = len(scan_results)
    for i, entry in enumerate(scan_results, start=1):
        label = f"{entry['product']} {entry['version']}".strip()
        cves = []
        if entry["product"]:
            if progress_callback:
                progress_callback(i, total, f"Looking up {label}")
            else:
                print(f"[*] Searching NVD for: {label}")
            cves = search_cves(entry["product"], entry["version"])
            time.sleep(0.8 if API_KEY != "YOUR_KEY_HERE" else 6)
        matched.append({**entry, "cves": cves})
    return matched
        
            
        
        
    
    
    
    