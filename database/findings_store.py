"""
database/findings_store.py
Stores ranked findings per scan, plus a registry with ONE row per finding.

It adds three new tables to your existing SQLite file and does not touch your
existing `scans` / `vulnerabilities` tables or db.py.

  scan_hosts        which hosts each scan covered (needed so a host that was
                    not rescanned is never wrongly reported as "fixed")
  scan_findings     the ranked findings of each scan (UNIQUE per scan+fingerprint)
  finding_registry  one row per finding across ALL scans: first_seen, last_seen,
                    times_seen, status (open / fixed). This is the de-duplication
                    of "the same CVE on rescans".
"""
from __future__ import annotations

import sqlite3
from typing import Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_runs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target     TEXT NOT NULL,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_hosts (
    scan_id INTEGER NOT NULL,
    host    TEXT    NOT NULL,
    UNIQUE (scan_id, host)
);

CREATE TABLE IF NOT EXISTS scan_findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER NOT NULL,
    fingerprint   TEXT    NOT NULL,
    host          TEXT    NOT NULL,
    port          INTEGER NOT NULL,
    protocol      TEXT    NOT NULL,
    service       TEXT,
    version       TEXT,
    cve_id        TEXT    NOT NULL,
    cvss          REAL    NOT NULL,
    cvss_version  TEXT,
    criticality   INTEGER NOT NULL,
    risk_score    REAL    NOT NULL,
    band          TEXT    NOT NULL,
    rank          INTEGER NOT NULL,
    evidence_hash TEXT    NOT NULL,
    UNIQUE (scan_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS finding_registry (
    fingerprint     TEXT PRIMARY KEY,
    host            TEXT    NOT NULL,
    port            INTEGER NOT NULL,
    protocol        TEXT    NOT NULL,
    service         TEXT,
    cve_id          TEXT    NOT NULL,
    cvss            REAL    NOT NULL,
    risk_score      REAL    NOT NULL,
    band            TEXT    NOT NULL,
    evidence_hash   TEXT    NOT NULL,
    first_seen_scan INTEGER NOT NULL,
    last_seen_scan  INTEGER NOT NULL,
    times_seen      INTEGER NOT NULL DEFAULT 1,
    status          TEXT    NOT NULL DEFAULT 'open',
    fixed_in_scan   INTEGER
);
"""


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


def connect(path: str = ":memory:") -> sqlite3.Connection:
    """Open the DB (your nvas .db file, or ':memory:' for tests) and make sure tables exist."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    init_schema(conn)
    return conn


def new_run(conn: sqlite3.Connection, target: str) -> int:
    """
    Start a new scan RUN and return its id.
    Your db.py `scans` table stores one row per port, so its id is not a run id;
    this table gives every full scan of a target its own id.
    """
    cur = conn.execute("INSERT INTO scan_runs (target) VALUES (?)", (target,))
    conn.commit()
    return cur.lastrowid


def previous_run_id(conn: sqlite3.Connection, target: str, before_id: int):
    """Latest earlier run of the SAME target, or None if this is the first one."""
    row = conn.execute("SELECT MAX(id) AS id FROM scan_runs WHERE target = ? AND id < ?",
                       (target, before_id)).fetchone()
    return row["id"]


def last_two_runs(conn: sqlite3.Connection, target: str):
    """(older_id, newer_id) for the two most recent runs of a target, or None."""
    rows = conn.execute("SELECT id FROM scan_runs WHERE target = ? ORDER BY id DESC LIMIT 2",
                        (target,)).fetchall()
    if len(rows) < 2:
        return None
    return rows[1]["id"], rows[0]["id"]


def _insert_finding(conn: sqlite3.Connection, scan_id: int, f) -> bool:
    """Store one finding for this scan. False if this scan already had it."""
    cur = conn.execute(
        """INSERT OR IGNORE INTO scan_findings
           (scan_id, fingerprint, host, port, protocol, service, version, cve_id,
            cvss, cvss_version, criticality, risk_score, band, rank, evidence_hash)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (scan_id, f.fingerprint, f.host, f.port, f.protocol, f.service, f.version,
         f.cve_id, f.cvss, f.cvss_version, f.criticality, f.risk_score, f.band,
         f.rank, f.evidence_hash))
    return cur.rowcount == 1


def _update_registry(conn: sqlite3.Connection, scan_id: int, f) -> None:
    """One registry row per finding: create it, or bump last_seen/times_seen."""
    conn.execute(
        """INSERT INTO finding_registry
           (fingerprint, host, port, protocol, service, cve_id, cvss, risk_score,
            band, evidence_hash, first_seen_scan, last_seen_scan, times_seen, status)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1,'open')
           ON CONFLICT(fingerprint) DO UPDATE SET
               service         = excluded.service,
               cvss            = excluded.cvss,
               risk_score      = excluded.risk_score,
               band            = excluded.band,
               evidence_hash   = excluded.evidence_hash,
               last_seen_scan  = excluded.last_seen_scan,
               times_seen      = finding_registry.times_seen + 1,
               status          = 'open',
               fixed_in_scan   = NULL""",
        (f.fingerprint, f.host, f.port, f.protocol, f.service, f.cve_id, f.cvss,
         f.risk_score, f.band, f.evidence_hash, scan_id, scan_id))


def _mark_fixed(conn: sqlite3.Connection, scan_id: int, hosts: list) -> int:
    """Open findings on a RESCANNED host that did not show up again are fixed."""
    if not hosts:
        return 0
    marks = ",".join("?" * len(hosts))
    cur = conn.execute(
        f"""UPDATE finding_registry SET status = 'fixed', fixed_in_scan = ?
            WHERE status = 'open' AND last_seen_scan < ? AND host IN ({marks})""",
        (scan_id, scan_id, *hosts))
    return cur.rowcount


def save_scan(conn: sqlite3.Connection, scan_id: int, findings: Iterable,
              scanned_hosts: Iterable[str]) -> dict:
    """
    Save the ranked findings of one scan and update the registry.
    Safe to call twice for the same scan_id (nothing is double counted).
    Returns {"saved": n, "newly_fixed": n}.
    """
    findings = list(findings)
    hosts = sorted(set(scanned_hosts) | {f.host for f in findings})
    saved = 0
    with conn:
        for host in hosts:
            conn.execute("INSERT OR IGNORE INTO scan_hosts (scan_id, host) VALUES (?, ?)",
                         (scan_id, host))
        for f in findings:
            if _insert_finding(conn, scan_id, f):
                saved += 1
                _update_registry(conn, scan_id, f)
        newly_fixed = _mark_fixed(conn, scan_id, hosts)
    return {"saved": saved, "newly_fixed": newly_fixed}


def load_scan_findings(conn: sqlite3.Connection, scan_id: int) -> list[dict]:
    rows = conn.execute("SELECT * FROM scan_findings WHERE scan_id = ? ORDER BY rank",
                        (scan_id,)).fetchall()
    return [dict(r) for r in rows]


def load_scan_hosts(conn: sqlite3.Connection, scan_id: int) -> set:
    rows = conn.execute("SELECT host FROM scan_hosts WHERE scan_id = ?", (scan_id,)).fetchall()
    return {r["host"] for r in rows}


def open_findings(conn: sqlite3.Connection) -> list[dict]:
    """The consolidated list: every currently open finding exactly once."""
    rows = conn.execute(
        "SELECT * FROM finding_registry WHERE status = 'open' "
        "ORDER BY risk_score DESC, host, port, cve_id").fetchall()
    return [dict(r) for r in rows]
