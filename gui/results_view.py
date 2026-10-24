import tkinter as tk
from tkinter import ttk

from analysis.risk_scorer import score_to_level

RISK_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# background and text colour for each risk level
RISK_COLORS = {
    "CRITICAL": ("#b71c1c", "white"),
    "HIGH": ("#e65100", "white"),
    "MEDIUM": ("#fbc02d", "black"),
    "LOW": ("#c8e6c9", "black"),
    "INFO": ("#eceff1", "black"),
}

# "INFO" means no CVE matched, which is not the same as "safe"
RISK_TEXT = {"INFO": "NO MATCH"}


def risk_text(level):
    return RISK_TEXT.get(level, level)


class ResultsView(tk.Frame):
    def __init__(self, parent, app, target, matched):
        super().__init__(parent, padx=30, pady=20)
        self.app = app
        self.rows = self.build_rows(matched)

        # Title row
        top = tk.Frame(self)
        top.pack(fill="x")
        tk.Label(top, text="Scan Results", font=("Segoe UI", 18, "bold")).pack(side="left")
        ttk.Button(top, text="New Scan", command=app.show_scan_view).pack(side="right")

        tk.Label(
            self,
            text=f"Target: {target}   |   {len(self.rows)} open ports",
            fg="#555555",
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(0, 10))

        self.build_summary()
        self.build_table()
        self.build_details()

        # Show the highest-risk port first
        if self.rows:
            self.table.selection_set("0")

    # ---------- data ----------

    def build_rows(self, matched):
        rows = []
        for entry in matched:
            cves = entry["cves"]
            scores = [c["cvss_score"] for c in cves if c["cvss_score"] is not None]
            top = max(scores) if scores else None
            rows.append({
                "port": entry["port"],
                "product": entry["product"] or entry["service"] or "unknown",
                "version": entry["version"],
                "cves": cves,
                "top_cvss": top,
                "level": score_to_level(top),
            })
        # highest CVSS first, ports with no score last
        rows.sort(key=lambda r: (r["top_cvss"] is None, -(r["top_cvss"] or 0), r["port"]))
        return rows

    # ---------- layout ----------

    def build_summary(self):
        bar = tk.Frame(self)
        bar.pack(fill="x", pady=(0, 10))
        for level in RISK_ORDER:
            count = sum(1 for r in self.rows if r["level"] == level)
            bg, fg = RISK_COLORS[level]
            tk.Label(
                bar,
                text=f"{risk_text(level)}: {count}",
                bg=bg,
                fg=fg,
                font=("Segoe UI", 10, "bold"),
                padx=14,
                pady=6,
            ).pack(side="left", padx=(0, 8))

    def build_table(self):
        frame = tk.Frame(self)
        frame.pack(fill="both", expand=True)

        columns = ("port", "product", "version", "cves", "cvss", "risk")
        self.table = ttk.Treeview(
            frame, columns=columns, show="headings", height=9, selectmode="browse"
        )
        headings = {
            "port": ("Port", 70),
            "product": ("Service", 230),
            "version": ("Version", 190),
            "cves": ("CVEs", 70),
            "cvss": ("Top CVSS", 90),
            "risk": ("Risk", 120),
        }
        for col, (text, width) in headings.items():
            self.table.heading(col, text=text)
            anchor = "w" if col in ("product", "version") else "center"
            self.table.column(col, width=width, anchor=anchor)

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scrollbar.set)
        self.table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        for level, (bg, fg) in RISK_COLORS.items():
            self.table.tag_configure(level, background=bg, foreground=fg)

        for index, row in enumerate(self.rows):
            top = row["top_cvss"] if row["top_cvss"] is not None else "-"
            self.table.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    row["port"],
                    row["product"],
                    row["version"],
                    len(row["cves"]),
                    top,
                    risk_text(row["level"]),
                ),
                tags=(row["level"],),
            )

        self.table.bind("<<TreeviewSelect>>", self.show_details)

    def build_details(self):
        tk.Label(
            self, text="Details (click a row above)", font=("Segoe UI", 10, "bold")
        ).pack(anchor="w", pady=(12, 4))

        self.details = tk.Text(
            self, height=10, wrap="word", font=("Segoe UI", 10), bg="#fafafa", state="disabled"
        )
        self.details.pack(fill="both", expand=True)
        self.details.tag_configure("title", font=("Segoe UI", 11, "bold"))
        self.details.tag_configure("cve", font=("Segoe UI", 10, "bold"))
        self.details.tag_configure("muted", foreground="#666666")

    # ---------- events ----------

    def show_details(self, event=None):
        selection = self.table.selection()
        if not selection:
            return
        row = self.rows[int(selection[0])]

        self.details.config(state="normal")
        self.details.delete("1.0", "end")

        title = f"Port {row['port']} - {row['product']} {row['version']}".strip()
        self.details.insert("end", title + "\n", "title")

        if not row["cves"]:
            self.details.insert("end", "\nNo matching CVEs were found for this service.\n")
            self.details.insert(
                "end",
                "This does not prove it is safe. It may mean the exact version "
                "could not be identified, so no match was possible.\n",
                "muted",
            )
        else:
            for cve in row["cves"]:
                score = cve["cvss_score"] if cve["cvss_score"] is not None else "n/a"
                severity = cve["severity"] or "n/a"
                self.details.insert(
                    "end", f"\n{cve['cve_id']}  ({severity}, CVSS {score})\n", "cve"
                )
                description = cve["description"]
                if len(description) > 300:
                    description = description[:300] + "..."
                self.details.insert("end", description + "\n")

        self.details.config(state="disabled")