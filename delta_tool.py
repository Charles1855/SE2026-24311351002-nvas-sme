"""
delta_tool.py  -  run risk prioritisation and delta reporting from the command line.

  python delta_tool.py demo
      Runs a full demonstration on built-in sample data (no VM needed).

  python delta_tool.py rank   --json findings.json [--criticality config/asset_criticality.json]
      Ranks findings from a JSON file (a list of finding objects).

  python delta_tool.py ingest --db nvas.db --scan 5 --json findings.json --hosts 192.168.56.102
      Ranks the findings and saves them as scan 5 (updates the registry).

  python delta_tool.py delta  --db nvas.db --old 4 --new 5 [--out reports]
      Writes the JSON + Markdown delta report for two saved scans.

  python delta_tool.py latest --target 192.168.56.102 [--db path] [--out reports]
      Compares the two most recent scans of a target recorded by the app.
      With no arguments at all, the demo runs.
"""
from __future__ import annotations

import argparse
import json
import sys

from analysis.delta import delta_from_db, render_markdown, write_report
from analysis.prioritiser import load_criticality, prioritise
from database import findings_store

CRIT_DEFAULT_PATH = "config/asset_criticality.json"


def _print_ranking(findings) -> None:
    print(f"{'#':>3}  {'Host:Port':<22} {'CVE':<16} {'CVSS':>5} {'Crit':>4} {'Risk':>5}  Band")
    for f in findings:
        print(f"{f.rank:>3}  {f.host + ':' + str(f.port):<22} {f.cve_id:<16} "
              f"{f.cvss:>5} {f.criticality:>4} {f.risk_score:>5}  {f.band}")


def _load_rows(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------- demo data
_HOST = "192.168.56.102"
_SCAN1 = [
    {"host": _HOST, "port": 21, "service": "ftp", "version": "vsftpd 2.3.4",
     "cve_id": "CVE-2011-2523", "cvss": 9.8},
    {"host": _HOST, "port": 22, "service": "ssh", "version": "OpenSSH 4.7p1",
     "cve_id": "CVE-2010-4478", "cvss": 7.5},
    {"host": _HOST, "port": 80, "service": "http", "version": "Apache 2.2.8",
     "cve_id": "CVE-2017-7679", "cvss": 9.8},
    {"host": _HOST, "port": 3306, "service": "mysql", "version": "MySQL 5.0.51a",
     "cve_id": "CVE-2012-2122", "cvss": 5.9},
    # duplicate of the vsftpd row: must collapse into one finding
    {"host": _HOST, "port": 21, "service": "ftp", "version": "vsftpd 2.3.4",
     "cve_id": "CVE-2011-2523", "cvss": 9.8},
]
_SCAN2 = [
    # vsftpd 2.3.4 removed -> FIXED
    {"host": _HOST, "port": 22, "service": "ssh", "version": "OpenSSH 4.7p1",
     "cve_id": "CVE-2010-4478", "cvss": 7.5},                      # persisting
    {"host": _HOST, "port": 80, "service": "http", "version": "Apache 2.2.8",
     "cve_id": "CVE-2017-7679", "cvss": 9.8},                      # persisting
    {"host": _HOST, "port": 3306, "service": "mysql", "version": "MySQL 5.0.95",
     "cve_id": "CVE-2012-2122", "cvss": 5.9},                      # persisting, evidence changed
    {"host": _HOST, "port": 80, "service": "http", "version": "Apache 2.2.8",
     "cve_id": "CVE-2011-3192", "cvss": 7.8, "cvss_version": "2.0"},  # NEW (v2 fallback)
]


def cmd_demo(_args) -> int:
    table = {"default": 3, _HOST: 4}
    conn = findings_store.connect(":memory:")

    print("=== Scan 1: ranked findings (duplicate input row collapsed) ===")
    first = prioritise(_SCAN1, table)
    _print_ranking(first)
    findings_store.save_scan(conn, 1, first, [_HOST])

    print("\n=== Same scan, rows shuffled: ranking must be identical ===")
    again = prioritise(list(reversed(_SCAN1)), table)
    print("Reproducible:", [f.fingerprint for f in first] == [f.fingerprint for f in again]
          and [f.rank for f in first] == [f.rank for f in again])

    print("\n=== Scan 2 (rescan) ===")
    second = prioritise(_SCAN2, table)
    _print_ranking(second)
    findings_store.save_scan(conn, 2, second, [_HOST])

    print("\n=== Registry after 2 scans: one row per finding (de-duplication) ===")
    for r in findings_store.open_findings(conn):
        print(f"  {r['cve_id']:<16} seen {r['times_seen']}x  first scan {r['first_seen_scan']}  "
              f"status {r['status']}")

    delta = delta_from_db(conn, 1, 2)
    jp, mp = write_report(delta, "reports")
    print("\n" + render_markdown(delta))
    print(f"Saved: {jp}\n       {mp}")
    return 0


def cmd_rank(args) -> int:
    table = load_criticality(args.criticality)
    _print_ranking(prioritise(_load_rows(args.json), table))
    return 0


def cmd_ingest(args) -> int:
    table = load_criticality(args.criticality)
    findings = prioritise(_load_rows(args.json), table)
    conn = findings_store.connect(args.db)
    hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
    result = findings_store.save_scan(conn, args.scan, findings, hosts)
    _print_ranking(findings)
    print(f"\nSaved scan {args.scan}: {result}")
    return 0


def cmd_delta(args) -> int:
    conn = findings_store.connect(args.db)
    delta = delta_from_db(conn, args.old, args.new)
    jp, mp = write_report(delta, args.out)
    print(render_markdown(delta))
    print(f"Saved: {jp}\n       {mp}")
    return 0


def cmd_latest(args) -> int:
    from database.db import DB_PATH
    conn = findings_store.connect(args.db or DB_PATH)
    pair = findings_store.last_two_runs(conn, args.target)
    if pair is None:
        print(f"Need at least two recorded scans of {args.target}; run the scan twice first.")
        return 1
    delta = delta_from_db(conn, pair[0], pair[1])
    jp, mp = write_report(delta, args.out)
    print(render_markdown(delta))
    print(f"Saved: {jp}\n       {mp}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="NVAS risk prioritisation and delta reporting")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("demo").set_defaults(func=cmd_demo)

    p = sub.add_parser("rank")
    p.add_argument("--json", required=True)
    p.add_argument("--criticality", default=CRIT_DEFAULT_PATH)
    p.set_defaults(func=cmd_rank)

    p = sub.add_parser("ingest")
    p.add_argument("--db", required=True)
    p.add_argument("--scan", type=int, required=True)
    p.add_argument("--json", required=True)
    p.add_argument("--hosts", required=True, help="comma-separated hosts this scan covered")
    p.add_argument("--criticality", default=CRIT_DEFAULT_PATH)
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("latest")
    p.add_argument("--target", required=True)
    p.add_argument("--db", default=None)
    p.add_argument("--out", default="reports")
    p.set_defaults(func=cmd_latest)

    p = sub.add_parser("delta")
    p.add_argument("--db", required=True)
    p.add_argument("--old", type=int, required=True)
    p.add_argument("--new", type=int, required=True)
    p.add_argument("--out", default="reports")
    p.set_defaults(func=cmd_delta)

    args = parser.parse_args(argv if argv is not None else (sys.argv[1:] or ["demo"]))
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())