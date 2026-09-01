from analysis.vuln_matcher import search_cves

results = search_cves("vsftpd", "2.3.4")
for r in results:
    print(r["cve_id"], r["severity"], r["description"][:80])