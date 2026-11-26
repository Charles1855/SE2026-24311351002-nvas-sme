"""
analysis/scan_integration.py
Connects the existing scan pipeline to risk prioritisation and delta reporting.

Where it plugs in
-----------------
Call record_scan(matched, target) once per finished scan, at the point where you
already have the matcher's output (`matched`, the same list you pass to
rank_findings) and the target IP.

    from analysis.scan_integration import record_scan
    result = record_scan(matched, target)
    result["findings"]   # ranked, de-duplicated findings (rank 1 = fix first)
    result["delta"]      # None on the first scan of a target, else new/fixed/persisting

`matched` is a list of per-service dicts:
    {"port", "product", "service", "version", "cves": [{"cve_id", "cvss_score",
     "description", "severity"}], "match_type"}
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional

from analysis.delta import delta_from_db, write_report
from analysis.prioritiser import load_criticality, prioritise
from database import findings_store
from database.db import DB_PATH

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CRITICALITY_PATH = ROOT / "config" / "asset_criticality.json"
DEFAULT_REPORT_DIR = ROOT / "reports"


def matched_to_rows(matched: Iterable[dict], target: str) -> list[dict]:
    """
    Flatten the matcher output (one dict per service, many CVEs each) into one
    row per CVE, which is what prioritise() expects. The matcher output has no
    host, so the scan target is added here (an entry may carry its own "host").
    Services with no CVEs produce no rows.
    """
    rows = []
    for entry in matched:
        for cve in entry.get("cves") or []:
            rows.append({
                "host": entry.get("host") or target,
                "port": entry["port"],
                "protocol": entry.get("protocol", "tcp"),
                "service": entry.get("product") or entry.get("service") or "",
                "version": entry.get("version") or "",
                "cve_id": cve["cve_id"],
                "cvss": cve.get("cvss_score") or 0.0,
                "cvss_version": cve.get("cvss_version", "3.1"),
                "description": cve.get("description") or "",
            })
    return rows


def record_scan(matched: Iterable[dict], target: str, db_path: Optional[str] = None,
                criticality_path: Optional[str] = None,
                report_dir: Optional[str] = None, write_reports: bool = True) -> dict:
    matched = list(matched)
    conn = findings_store.connect(db_path or DB_PATH)
    try:
        table = load_criticality(criticality_path or DEFAULT_CRITICALITY_PATH)
        findings = prioritise(matched_to_rows(matched, target), table)

        run_id = findings_store.new_run(conn, target)
        hosts = {target} | {e["host"] for e in matched if e.get("host")}
        findings_store.save_scan(conn, run_id, findings, hosts)

        previous = findings_store.previous_run_id(conn, target, run_id)
        delta, report_paths = None, None
        if previous is not None:
            delta = delta_from_db(conn, previous, run_id)
            if write_reports:
                report_paths = write_report(delta, report_dir or DEFAULT_REPORT_DIR)
        return {"run_id": run_id, "previous_run_id": previous, "findings": findings,
                "delta": delta, "report_paths": report_paths}
    finally:
        conn.close()
