from scanner.port_scanner import PortScanner
from analysis.vuln_matcher import match_scan_results
from database.db import init_db, save_scan_result

TARGET = "192.168.56.101"

init_db()

scanner = PortScanner()
scan_results = scanner.scan_target(TARGET)

print(f"\n[*] Found {len(scan_results)} open ports. Matching against NVD...\n")

matched = match_scan_results(scan_results)

for entry in matched:
    save_scan_result(
        target=TARGET,
        port=entry["port"],
        service=entry["service"],
        product=entry["product"],
        version=entry["version"],
        cves=entry["cves"]
    )
    print(f"\nPort {entry['port']} - {entry['product']} {entry['version']}")
    if not entry["cves"]:
        print("  No CVEs found")
    for cve in entry["cves"]:
        print(f"  {cve['cve_id']} ({cve['severity']}) - CVSS {cve['cvss_score']}")

print("\n[+] Results saved to database/vuln_assessment.db")