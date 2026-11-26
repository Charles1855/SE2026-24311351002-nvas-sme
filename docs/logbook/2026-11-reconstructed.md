# Logbook: reconstructed entry (earlier sessions)

Written on 2026-11-23 from `git log`. This is not a contemporaneous log. It lists what the commit history shows, not session lengths or notes I did not record at the time.

## Commit history
2026-08-30 80d28b5 initial commit
2026-08-31 24bf916 feat: implement host and port scanner with service version detection
2026-09-01 88b1b27 added a method that returns a list of dicts alongside the print output, since vuln_scanner.py requires structured data to work with, not a printed string
2026-09-01 1081096  start CVE matcher, keyword search not yet validated
2026-09-01 7188e0f severity labels like HIGH MEDIUM etc instead of none
2026-09-01 97b8a37 chore: ignore __pycache__ and compiled files
2026-09-01 60cec92 chore: add .venv and .env to .gitignore
2026-09-01 c2c12d2 feat: add main.py as project entry point
2026-09-01 fb7699a fix: re-save .gitignore as UTF-8 (was UTF-16, patterns not matching)
2026-09-01 4ef184c chore: mark analysis as package, add vuln_matcher tests
2026-09-01 494971a feat: add SQLite storage for scan results and CVE matches
2026-09-02 f9ce0a0 feat: add per-port risk scoring based on max CVSS
2026-10-24 0ea9cb6 refactor: improve CVE matching logic in vuln_matcher
2026-10-24 755205b chore: stop tracking SQLite database file and ignore *.db
2026-10-24 201a126 refactor: update risk scoring logic
2026-10-24 762f047 refactor: merge service detection into port_scanner and remove service_detector
2026-10-24 3cc0865 feat: build Tkinter GUI with scan and results views
2026-10-24 3726659 feat: add gui_main.py as GUI entry point
2026-10-24 90e51db chore: ignore SQLite database files
2026-11-05 fed2277 chore: add config template for NVD API key
2026-11-05 de446ed feat: return CPE for each service and remove unused code
2026-11-05 10fedd1 feat: match CVEs by CPE with keyword fallback
2026-11-05 311506f feat: add shared GUI theme
2026-11-05 943311f feat: add ranked results table with match confidence
2026-11-05 22991e3 feat: add scan steps, timer and coloured activity log
2026-11-05 2612a63 feat: add header and status footer to main window
2026-11-05 2f24663 Updated README for Network Vulnerability Assessment System
2026-11-05 fa792cf chore: add script to clear the results database
2026-11-05 b634cdf docs: add project overview and setup guide
2026-11-05 e5e48ce chore: remove main.py, replaced by gui_main.py
2026-11-05 120c3f2 Merge branch 'main' of https://github.com/Charles1855/Network-Vulnerability-System
2026-11-05 4f71be8 fix: remove API key from config template
2026-11-05 eb9ed92 chore: ignore local config file with API key
2026-11-19 49b955f refactor: add shared rank_findings for results and report
2026-11-19 b1ad4ec feat: generate PDF assessment report
2026-11-19 f64b471 test: add tests for ranking and PDF report
2026-11-19 de36097 feat: add Export PDF button to results screen
2026-11-19 b9ffaef chore: ignore generated reports
2026-11-20 4f71cec chore: ignore logs and the authoriser's private key
2026-11-20 f128fa6 chore: add cryptography and dev tool requirements
2026-11-20 0bfcd46 feat: add signed scope guard with audit log
2026-11-20 e33d0bd feat: require the scope guard before any scan
2026-11-20 11052e0 feat: add tool to create, sign and check scope files
2026-11-20 d55c46e test: add scope guard and scanner tests
2026-11-20 bd4f4f0 test: add BDD scenarios for scope enforcement
2026-11-20 c84ee59 feat: block out-of-scope targets in the GUI
2026-11-20 0fcce4f chore: add demo scope and public key
2026-11-22 ae72f71 feat: add scrypt password hashing and policy
2026-11-22 f692b64 feat: add account and security event storage
2026-11-22 e962738 feat: add sign-in, roles, lockout and account management
2026-11-22 4ea10a2 feat: record who ran each scan in the audit log and report
2026-11-22 9252f6b feat: add sign-in screen, user management and role-based scanning
2026-11-22 fbf630a test: add authentication and audit tests
2026-11-22 3bc7710 test: add BDD scenarios for authentication
2026-11-23 0cf7b51 fix: close database handle in password storage test