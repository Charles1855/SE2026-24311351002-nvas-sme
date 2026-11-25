"""
analysis/delta.py
Delta reporting for NVAS  (Signature Challenge, property 4)

Compares two scans and reports:
    NEW         in the newer scan, not in the older one
    FIXED       in the older scan, gone from the newer one
    PERSISTING  in both scans
Every finding carries its SHA-256 evidence hash. For persisting findings the
report also shows the previous hash and whether the evidence changed
(e.g. the service version or CVSS score changed between scans).

Fairness rule: a finding is only called FIXED if its host was scanned again.
A host that was not rescanned goes in `hosts_not_rescanned`, not in FIXED.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from database import findings_store


def _entry(f: dict) -> dict:
    return {
        "fingerprint": f["fingerprint"],
        "host": f["host"],
        "port": f["port"],
        "protocol": f["protocol"],
        "service": f.get("service", ""),
        "cve_id": f["cve_id"],
        "cvss": f["cvss"],
        "cvss_version": f.get("cvss_version") or "3.1",
        "risk_score": f["risk_score"],
        "band": f["band"],
        "evidence_hash": f["evidence_hash"],
    }


def _order(entries: list[dict]) -> list[dict]:
    return sorted(entries, key=lambda e: (-e["risk_score"], e["host"], e["port"], e["cve_id"]))


def compute_delta(old_findings: Iterable[dict], new_findings: Iterable[dict],
                  old_hosts: Iterable[str], new_hosts: Iterable[str],
                  old_scan=None, new_scan=None,
                  generated_at: Optional[str] = None) -> dict:
    old_hosts, new_hosts = set(old_hosts), set(new_hosts)
    common = old_hosts & new_hosts

    old_map = {f["fingerprint"]: f for f in old_findings if f["host"] in common}
    new_map = {f["fingerprint"]: f for f in new_findings}

    new_items = [_entry(new_map[fp]) for fp in new_map.keys() - old_map.keys()]
    fixed_items = [_entry(old_map[fp]) for fp in old_map.keys() - new_map.keys()]

    persisting_items = []
    for fp in new_map.keys() & old_map.keys():
        item = _entry(new_map[fp])
        previous = old_map[fp]["evidence_hash"]
        item["previous_evidence_hash"] = previous
        item["evidence_changed"] = previous != item["evidence_hash"]
        persisting_items.append(item)

    new_items, fixed_items, persisting_items = map(_order, (new_items, fixed_items, persisting_items))

    return {
        "old_scan": old_scan,
        "new_scan": new_scan,
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "hosts_compared": sorted(common),
        "hosts_added": sorted(new_hosts - old_hosts),
        "hosts_not_rescanned": sorted(old_hosts - new_hosts),
        "summary": {
            "new": len(new_items),
            "fixed": len(fixed_items),
            "persisting": len(persisting_items),
        },
        "new": new_items,
        "fixed": fixed_items,
        "persisting": persisting_items,
    }


def delta_from_db(conn, old_scan_id: int, new_scan_id: int) -> dict:
    old_hosts = findings_store.load_scan_hosts(conn, old_scan_id)
    new_hosts = findings_store.load_scan_hosts(conn, new_scan_id)
    if not old_hosts:
        raise ValueError(f"scan {old_scan_id} has no saved findings/hosts")
    if not new_hosts:
        raise ValueError(f"scan {new_scan_id} has no saved findings/hosts")
    return compute_delta(
        findings_store.load_scan_findings(conn, old_scan_id),
        findings_store.load_scan_findings(conn, new_scan_id),
        old_hosts, new_hosts, old_scan_id, new_scan_id)


def _md_table(title: str, rows: list[dict], with_change_flag: bool = False) -> list[str]:
    lines = [f"## {title} ({len(rows)})", ""]
    if not rows:
        return lines + ["_None._", ""]
    head = "| Host:Port | CVE | CVSS (version) | Risk | Band | Evidence hash (SHA-256, first 16) |"
    sep = "|---|---|---|---|---|---|"
    if with_change_flag:
        head = head + " Evidence changed |"
        sep += "---|"
    lines += [head, sep]
    for r in rows:
        line = (f"| {r['host']}:{r['port']}/{r['protocol']} | {r['cve_id']} | {r['cvss']} (v{r['cvss_version']}) | "
                f"{r['risk_score']} | {r['band']} | `{r['evidence_hash'][:16]}` |")
        if with_change_flag:
            line += f" {'yes' if r['evidence_changed'] else 'no'} |"
        lines.append(line)
    return lines + [""]


def render_markdown(delta: dict) -> str:
    s = delta["summary"]
    lines = [
        f"# Delta report: scan {delta['old_scan']} to scan {delta['new_scan']}",
        "",
        f"Generated: {delta['generated_at']}",
        "",
        f"**New: {s['new']}  |  Fixed: {s['fixed']}  |  Persisting: {s['persisting']}**",
        "",
        f"Hosts compared: {', '.join(delta['hosts_compared']) or 'none'}",
    ]
    if delta["hosts_added"]:
        lines.append(f"New hosts in this scan: {', '.join(delta['hosts_added'])}")
    if delta["hosts_not_rescanned"]:
        lines.append("Not rescanned (excluded from FIXED): " + ", ".join(delta["hosts_not_rescanned"]))
    lines.append("")
    lines += _md_table("New findings", delta["new"])
    lines += _md_table("Fixed findings", delta["fixed"])
    lines += _md_table("Persisting findings", delta["persisting"], with_change_flag=True)
    lines.append("Full 64-character hashes are in the JSON report.")
    return "\n".join(lines) + "\n"


def write_report(delta: dict, out_dir: str | Path = "reports") -> tuple[Path, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stem = f"delta_scan{delta['old_scan']}_to_scan{delta['new_scan']}"
    json_path, md_path = out / f"{stem}.json", out / f"{stem}.md"
    json_path.write_text(json.dumps(delta, indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(delta), encoding="utf-8")
    return json_path, md_path
