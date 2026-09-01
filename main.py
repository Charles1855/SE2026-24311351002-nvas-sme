from scanner.port_scanner import PortScanner
from analysis.vuln_matcher import match_scan_results

TARGET = "192.168.56.101"

scanner = PortScanner()
scan_results = scanner.scan_target(TARGET)

print(f"\n[*] Found {len(scan_results)} open ports. Matching against NVD...\n")

matched = match_scan_results(scan_results)

for entry in matched:
    print(f"\nPort {entry['port']} - {entry['product']} {entry['version']}")
    if not entry["cves"]:
        print(" No CVEs found")
    for cve in entry["cves"]:
        print(f" {cve['cve_id']} ({cve['severity']}) - CVSS {cve['cvss_score']}")
        