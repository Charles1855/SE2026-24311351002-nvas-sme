"""
analysis/prioritiser.py
Risk prioritisation for NVAS  (Signature Challenge, property 3)

What this module guarantees
---------------------------
1. Scores come from the CVSS v3.1 base score and an asset criticality (1-5).
2. The ranking is REPRODUCIBLE: same input -> same output, in any input order.
   The sort has a fixed tie-break chain, so no two findings are ever "equal".
3. The same CVE on the same host/port is DE-DUPLICATED (one finding per
   fingerprint), both inside one scan and, via findings_store.py, across rescans.

Formula (kept simple so you can defend it in the review)
--------------------------------------------------------
    raw_score  = round(cvss_base * multiplier[criticality], 2)
    risk_score = min(10.0, raw_score)

    criticality : 1     2     3 (default)   4     5
    multiplier  : 0.8   0.9   1.0           1.1   1.2   (+/-10% per level)

Bands reuse the thresholds already in risk_scorer.py:
    >= 9.0 CRITICAL, >= 7.0 HIGH, >= 4.0 MEDIUM, > 0 LOW, 0 INFO
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Optional

CRITICALITY_MULTIPLIER = {1: 0.8, 2: 0.9, 3: 1.0, 4: 1.1, 5: 1.2}
DEFAULT_CRITICALITY = 3


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def severity_band(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"


def validate_criticality(value) -> int:
    try:
        level = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"asset criticality must be an integer 1-5, got {value!r}")
    if level not in CRITICALITY_MULTIPLIER:
        raise ValueError(f"asset criticality must be 1-5, got {level}")
    return level


def load_criticality(path: Optional[str | Path] = None) -> dict:
    """
    Load asset criticality from a JSON file such as:
        {"default": 3, "192.168.56.102": 5, "192.168.56.1": 1}
    A missing file or path gives {"default": 3}.
    """
    if path is None or not Path(path).exists():
        return {"default": DEFAULT_CRITICALITY}
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    table = {str(k): validate_criticality(v) for k, v in data.items()}
    table.setdefault("default", DEFAULT_CRITICALITY)
    return table


def criticality_for(host: str, table: Optional[dict]) -> int:
    table = table or {}
    return validate_criticality(table.get(host, table.get("default", DEFAULT_CRITICALITY)))


def make_fingerprint(host: str, port: int, protocol: str, cve_id: str) -> str:
    """Identity of a finding: the SAME host + port + protocol + CVE is the same finding."""
    key = f"{host}|{int(port)}|{protocol.lower()}|{cve_id.upper()}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def make_evidence_hash(host, port, protocol, service, version, banner,
                       cve_id, cvss, cvss_version) -> str:
    """
    SHA-256 over the canonical (sorted-key JSON) evidence for a finding.
    No timestamps on purpose: an unchanged finding keeps the same hash on every
    rescan, and the hash changes only if the evidence itself changes
    (e.g. the service version or the CVSS score).
    """
    evidence = {
        "host": host, "port": int(port), "protocol": protocol.lower(),
        "service": service, "version": version, "banner": banner,
        "cve_id": cve_id.upper(), "cvss": float(cvss), "cvss_version": str(cvss_version),
    }
    blob = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Finding record
# --------------------------------------------------------------------------
@dataclass
class Finding:
    host: str
    port: int
    protocol: str
    service: str
    version: str
    banner: str
    cve_id: str
    cvss: float
    cvss_version: str
    description: str
    fingerprint: str
    evidence_hash: str
    criticality: int = DEFAULT_CRITICALITY
    raw_score: float = 0.0
    risk_score: float = 0.0
    band: str = "INFO"
    rank: int = 0
    score_basis: str = "CVSS v3.1"

    def to_dict(self) -> dict:
        return asdict(self)


def _pick(raw: dict, names: Iterable[str], default=None):
    """Return the first non-empty value among several possible key names."""
    for name in names:
        if name in raw and raw[name] not in (None, ""):
            return raw[name]
    return default


def normalise_finding(raw) -> Optional[Finding]:
    """
    Turn one row (dict or sqlite3.Row) from your pipeline into a Finding.
    Accepts several key spellings so it fits your existing code without changes:
      host: host / ip / ip_address / target        port: port / portid
      cve: cve_id / cve                            cvss: cvss / cvss_score / cvss_base / base_score
    Rows with no CVE (ports where the NVD matched nothing) return None.
    """
    raw = dict(raw)
    cve = _pick(raw, ("cve_id", "cve", "CVE"))
    if not cve:
        return None
    cve = str(cve).strip().upper()

    host = _pick(raw, ("host", "ip", "ip_address", "target"))
    if not host:
        raise ValueError("finding has no host/ip")
    host = str(host).strip()

    port = _pick(raw, ("port", "portid"))
    if port is None:
        raise ValueError(f"finding {cve} on {host} has no port")
    port = int(port)

    cvss = float(_pick(raw, ("cvss", "cvss_score", "cvss_base", "base_score"), 0.0))
    if not 0.0 <= cvss <= 10.0:
        raise ValueError(f"CVSS score out of range 0-10: {cvss}")

    cvss_version = str(_pick(raw, ("cvss_version",), "3.1"))
    protocol = str(_pick(raw, ("protocol", "proto"), "tcp")).lower()
    service = str(_pick(raw, ("service", "service_name", "name"), ""))
    version = str(_pick(raw, ("version", "service_version", "product_version"), ""))
    banner = str(_pick(raw, ("banner", "evidence", "extrainfo"), ""))
    description = str(_pick(raw, ("description", "summary"), ""))

    basis = "CVSS v3.1" if cvss_version.startswith("3") else f"CVSS v{cvss_version} (fallback)"

    return Finding(
        host=host, port=port, protocol=protocol, service=service, version=version,
        banner=banner, cve_id=cve, cvss=cvss, cvss_version=cvss_version,
        description=description,
        fingerprint=make_fingerprint(host, port, protocol, cve),
        evidence_hash=make_evidence_hash(host, port, protocol, service, version,
                                         banner, cve, cvss, cvss_version),
        score_basis=basis,
    )


# --------------------------------------------------------------------------
# Scoring and ranking
# --------------------------------------------------------------------------
def score_finding(cvss: float, criticality: int) -> tuple[float, float]:
    """Return (raw_score, risk_score). risk_score is raw_score capped at 10."""
    raw = round(cvss * CRITICALITY_MULTIPLIER[validate_criticality(criticality)], 2)
    return raw, min(10.0, raw)


def _host_key(host: str) -> tuple:
    try:
        return (0, int(ipaddress.ip_address(host)), "")
    except ValueError:
        return (1, 0, host)


def _sort_key(f: Finding) -> tuple:
    # Highest raw score first. Everything after that only breaks ties and
    # makes the order fully deterministic.
    return (-f.raw_score, -f.cvss, _host_key(f.host), f.port, f.protocol, f.cve_id)


def prioritise(rows: Iterable, criticality_table: Optional[dict] = None) -> list[Finding]:
    """
    rows -> de-duplicated, scored, ranked list of Finding (rank 1 = fix first).
    Duplicates (same fingerprint) collapse to one finding; the one with the higher
    CVSS wins, with a fixed tie-break so input order never matters.
    """
    table = criticality_table or {"default": DEFAULT_CRITICALITY}
    best: dict[str, Finding] = {}
    for raw in rows:
        f = normalise_finding(raw)
        if f is None:
            continue
        current = best.get(f.fingerprint)
        if current is None or (f.cvss, f.evidence_hash, f.description) > (
                current.cvss, current.evidence_hash, current.description):
            best[f.fingerprint] = f

    findings = list(best.values())
    for f in findings:
        f.criticality = criticality_for(f.host, table)
        f.raw_score, f.risk_score = score_finding(f.cvss, f.criticality)
        f.band = severity_band(f.risk_score)
    findings.sort(key=_sort_key)
    for position, f in enumerate(findings, start=1):
        f.rank = position
    return findings