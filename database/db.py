import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "vuln_assessment.db")

def get_connection():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            port INTEGER NOT NULL,
            service TEXT,
            product TEXT,
            version TEXT,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            cve_id TEXT NOT NULL,
            description TEXT,
            cvss_score REAL,
            severity TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    conn.commit()
    conn.close()

def save_scan_result(target, port, service, product, version, cves):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scans (target, port, service, product, version)
        VALUES (?, ?, ?, ?, ?)
    """, (target, port, service, product, version))

    scan_id = cursor.lastrowid

    for cve in cves:
        cursor.execute("""
            INSERT INTO vulnerabilities (scan_id, cve_id, description, cvss_score, severity)
            VALUES (?, ?, ?, ?, ?)
        """, (scan_id, cve["cve_id"], cve["description"], cve["cvss_score"], cve["severity"]))

    conn.commit()
    conn.close()

def get_all_findings():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT scans.target, scans.port, scans.product, scans.version,
               vulnerabilities.cve_id, vulnerabilities.severity, vulnerabilities.cvss_score
        FROM scans
        LEFT JOIN vulnerabilities ON scans.id = vulnerabilities.scan_id
        ORDER BY vulnerabilities.cvss_score DESC
    """)

    rows = cursor.fetchall()
    conn.close()
    return rows