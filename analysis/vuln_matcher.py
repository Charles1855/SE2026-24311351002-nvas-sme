import os
import re
import time

import requests

try:
    from config import NVD_API_KEY      # your key lives in config.py (not on GitHub)
except ImportError:
    NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEEP_PER_SERVICE = 10  # keep the highest-scoring CVEs for each service

# NVD metric key -> CVSS version label. Only 3.1 satisfies "CVSS v3.1 base score";
# anything else is kept as a fallback and labelled as such downstream.
CVSS_VERSIONS = {"cvssMetricV31": "3.1", "cvssMetricV30": "3.0",
                 "cvssMetricV40": "4.0", "cvssMetricV2": "2.0"}

HAS_KEY = bool(NVD_API_KEY) and NVD_API_KEY != ""
# NVD allows 50 requests per 30 s with a key and 5 per 30 s without one
REQUEST_DELAY = 0.8 if HAS_KEY else 6.5

_last_request = 0.0
warning_hook = None  # the GUI sets this so NVD problems show in its activity log
lookup_failures = 0  # NVD requests that failed after every retry; reset for each scan


# ---------- talking to NVD ----------

def _warn(text):
    print(text)
    if warning_hook:
        warning_hook(text)


def _throttle():
    """Wait just long enough to stay inside NVD's rate limit."""
    global _last_request
    wait = REQUEST_DELAY - (time.time() - _last_request)
    if wait > 0:
        time.sleep(wait)
    _last_request = time.time()


def _request(params, retries=3):
    """Call the NVD API. Returns the JSON, or None if it failed or found nothing."""
    global lookup_failures
    headers = {"apiKey": NVD_API_KEY} if HAS_KEY else {}
    for attempt in range(1, retries + 1):
        _throttle()
        try:
            response = requests.get(
                NVD_API_URL, params=params, headers=headers, timeout=15
            )
            if response.status_code == 404:
                # NVD answers 404 for a CPE it does not know (or a refused API key)
                if "keywordSearch" in params:
                    _warn("  [!] NVD returned 404 for a keyword search. Check your API key.")
                return None
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as error:
            _warn(f"  [!] NVD request failed (attempt {attempt}/{retries}): {error}")
            if attempt < retries:
                time.sleep(3)
    lookup_failures += 1  # "no answer" is not the same as "no vulnerabilities"
    return None


def _parse(data, keep):
    """Turn NVD's JSON into a short list of CVEs, highest CVSS score first."""
    matches = []
    for item in (data or {}).get("vulnerabilities", []):
        cve = item["cve"]
        metrics = cve.get("metrics", {})

        score, severity, cvss_version = None, None, None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
            if key in metrics:
                metric = metrics[key][0]
                cvss_version = CVSS_VERSIONS[key]
                score = metric["cvssData"]["baseScore"]
                # v3/v4 keep baseSeverity inside cvssData, v2 keeps it beside it
                severity = metric["cvssData"].get("baseSeverity") or metric.get("baseSeverity")
                break

        description = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "",
        )
        matches.append({
            "cve_id": cve["id"],
            "description": description,
            "cvss_score": score,
            "cvss_version": cvss_version,
            "severity": severity,
        })

    matches.sort(key=lambda m: m["cvss_score"] or 0, reverse=True)
    return matches[:keep]


def search_cves(product, version, max_results=5):
    """Keyword search. Used when there is no usable CPE."""
    query = f"{product} {version}".strip()
    data = _request({"keywordSearch": query, "resultsPerPage": 20})
    return _parse(data, max_results)


def search_cves_by_cpe(cpe23):
    """Exact search by CPE name. Far more precise than keywords."""
    data = _request({"cpeName": cpe23, "resultsPerPage": 500})
    return _parse(data, KEEP_PER_SERVICE)


# ---------- preparing the search terms ----------

def clean_version(raw):
    """
    Keep only a real version number.
      '4.7p1 Debian 8ubuntu1' -> '4.7p1'
      '5.0.51a-3ubuntu5'      -> '5.0.51a'
      '8.3.0 - 8.3.7'         -> '8.3.0'
      '3.X - 4.X' or 'v1'     -> ''   (not a usable version)
    """
    if not raw:
        return ""
    first = raw.split()[0].split("-")[0]
    return first if re.fullmatch(r"\d+(\.\d+)*[a-z]?\d*", first) else ""


def build_cpe23(nmap_cpe, version):
    """
    Convert nmap's CPE (2.2 style) into the CPE 2.3 name that NVD expects:
      cpe:/a:apache:http_server:2.2.8
      -> cpe:2.3:a:apache:http_server:2.2.8:*:*:*:*:*:*:*
    Only application CPEs (cpe:/a:) are used. nmap sometimes returns the
    operating system instead (cpe:/o:), which says nothing about the service.
    Returns None when there is no usable CPE or no version.
    """
    for token in str(nmap_cpe or "").split():
        if not token.startswith("cpe:/a:"):
            continue
        parts = token[len("cpe:/"):].split(":")  # ['a', 'apache', 'http_server', '2.2.8']
        if len(parts) < 3:
            continue
        vendor, product = parts[1], parts[2]
        cpe_version = parts[3] if len(parts) > 3 else ""
        use_version = clean_version(version) or clean_version(cpe_version)
        if not use_version:
            return None
        return f"cpe:2.3:a:{vendor}:{product}:{use_version}:*:*:*:*:*:*:*"
    return None


def find_cves(entry):
    """
    Try the most precise method first.
    Returns (list of CVEs, how they were matched).
    """
    version = clean_version(entry["version"])
    cpe23 = build_cpe23(entry.get("cpe", ""), entry["version"])

    if cpe23:
        cves = search_cves_by_cpe(cpe23)
        if cves:
            return cves, "CPE"

    cves = search_cves(entry["product"], version)
    if cves:
        return cves, ("Keyword + version" if version else "Name only")
    return [], ""


def match_scan_results(scan_results, progress_callback=None):
    global lookup_failures
    lookup_failures = 0
    matched = []
    total = len(scan_results)
    for i, entry in enumerate(scan_results, start=1):
        cves, match_type = [], ""
        if entry["product"]:
            label = f"{entry['product']} {entry['version']}".strip()
            if progress_callback:
                progress_callback(i, total, f"Looking up {label}")
            else:
                print(f"[*] Looking up {label}")
            cves, match_type = find_cves(entry)
        matched.append({**entry, "cves": cves, "match_type": match_type})
    return matched