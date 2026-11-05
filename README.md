# Network Vulnerability Assessment System

A desktop tool that scans a device on your network, identifies the services it
runs, looks up known vulnerabilities (CVEs) for those services in the US National
Vulnerability Database (NVD), and ranks the findings by risk using CVSS scores.

Built in Python with a Tkinter interface as a Computer Science undergraduate project.

## How it works

1. **Port scan** - python-nmap runs `nmap -sV` to find open ports and detect each
   service's product, version and CPE identifier.
2. **CVE lookup** - each service is matched against NVD. It tries an exact CPE
   search first and falls back to a keyword search. Every result records how it was
   matched (CPE, Keyword + version, or Name only), so confidence is visible.
3. **Risk scoring** - a port's risk level comes from its highest CVSS score
   (CRITICAL 9.0+, HIGH 7.0+, MEDIUM 4.0+, LOW below 4.0).
4. **Storage** - results are saved to a local SQLite database.
5. **Results screen** - ports are ranked worst first, with CVE details and links to NVD.

## Requirements

- Windows, Python 3.10 or newer
- [Nmap](https://nmap.org/download.html) installed and available on PATH
- A free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key)
  (it works without one, but lookups are much slower)

## Setup

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy config.example.py config.py
```

Open `config.py` and paste your NVD API key. Then start the app:

```
python gui_main.py
```

## Safe test target

Do not scan systems you do not own or have permission to test. For testing, use
[Metasploitable2](https://sourceforge.net/projects/metasploitable/) in VirtualBox on a
Host-Only network (for example `192.168.56.101`).

## Project structure

```
gui_main.py            starts the application
gui/                   Tkinter screens (scan, results, theme)
scanner/               port scanning and service detection (python-nmap)
analysis/              NVD matching (vuln_matcher) and risk scoring (risk_scorer)
database/              SQLite storage (db.py)
test_vuln_matcher.py   standalone check of keyword matching
test_cpe_matcher.py    standalone check of CPE matching
reset_db.py            empties the results database
```

## Known limitations

- Matching depends on what nmap can identify. Vague versions (for example Samba
  `3.X - 4.X`) cannot be matched, so a result of NO MATCH does not mean a service is safe.
- "Name only" matches are low confidence: they mention the service name but the
  exact version is unknown.
- It reports known, published vulnerabilities. It does not detect intrusions,
  malware, or unknown flaws.

## Planned work

- Scan history screen
- PDF report export