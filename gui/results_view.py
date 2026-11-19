import os
import tkinter as tk
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from analysis.report_generator import default_filename, generate_report
from analysis.risk_scorer import rank_findings
from gui import theme

NVD_URL = "https://nvd.nist.gov/vuln/detail/"
LOW_CONFIDENCE = "Name only"


class ResultsView(tk.Frame):
    def __init__(self, parent, app, target, matched, info=None):
        super().__init__(parent, bg=theme.BG, padx=32, pady=14)
        self.app = app
        self.target = target
        self.matched = matched
        self.info = info or {}
        self.rows = rank_findings(matched)
        info = self.info

        # ---- title row ----
        top = tk.Frame(self, bg=theme.BG)
        top.pack(fill="x")
        tk.Label(
            top, text="Scan Results", bg=theme.BG, fg=theme.TEXT,
            font=(theme.FONT, 20, "bold"),
        ).pack(side="left")
        ttk.Button(top, text="New Scan", command=app.show_scan_view).pack(side="right")
        ttk.Button(
            top, text="Export PDF", style="Accent.TButton", command=self.export_pdf
        ).pack(side="right", padx=(0, 10))

        parts = [f"Target {target}", f"{len(self.rows)} open ports"]
        if info.get("finished"):
            parts.append(f"scanned at {info['finished'].strftime('%H:%M')}")
        if info.get("seconds") is not None:
            parts.append(f"took {info['seconds']}s")
        tk.Label(
            self, text="   \u00b7   ".join(parts), bg=theme.BG, fg=theme.MUTED,
            font=(theme.FONT, 10),
        ).pack(anchor="w", pady=(0, 8))

        self.build_summary()
        self.build_table()
        self.build_details()

        # Start with the highest-risk port selected
        if self.rows:
            self.table.selection_set("0")

    # ---------- layout ----------

    def build_summary(self):
        bar = tk.Frame(self, bg=theme.BG)
        bar.pack(fill="x", pady=(0, 10))
        for column, level in enumerate(theme.RISK_ORDER):
            bar.columnconfigure(column, weight=1, uniform="cards")
            count = sum(1 for r in self.rows if r["level"] == level)
            bg, fg = theme.RISK_COLORS[level]
            card = tk.Frame(bar, bg=bg)
            card.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 8, 0))
            tk.Label(
                card, text=str(count), bg=bg, fg=fg, font=(theme.FONT, 18, "bold")
            ).pack(pady=(4, 0))
            tk.Label(
                card, text=theme.risk_label(level), bg=bg, fg=fg,
                font=(theme.FONT, 9, "bold"),
            ).pack(pady=(0, 4))

    def build_table(self):
        frame = tk.Frame(
            self, bg=theme.CARD, highlightbackground=theme.BORDER,
            highlightcolor=theme.BORDER, highlightthickness=1,
        )
        frame.pack(fill="x")  # fixed height: spare window room goes to the details panel

        columns = ("rank", "port", "product", "version", "cves", "cvss", "risk", "match")
        self.table = ttk.Treeview(
            frame, columns=columns, show="headings", height=6, selectmode="browse"
        )
        headings = {
            "rank": ("#", 46),
            "port": ("Port", 64),
            "product": ("Service", 220),
            "version": ("Version", 150),
            "cves": ("CVEs", 56),
            "cvss": ("Top CVSS", 84),
            "risk": ("Risk", 100),
            "match": ("Match", 140),
        }
        for col, (text, width) in headings.items():
            self.table.heading(col, text=text)
            anchor = "w" if col in ("product", "version", "match") else "center"
            self.table.column(col, width=width, anchor=anchor)

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scrollbar.set)
        self.table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        for level, (bg, fg) in theme.RISK_COLORS.items():
            self.table.tag_configure(level, background=bg, foreground=fg)

        for index, row in enumerate(self.rows):
            rank_text = str(row["rank"]) if row["rank"] else "-"
            top = row["top_cvss"] if row["top_cvss"] is not None else "-"
            self.table.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    rank_text,
                    row["port"],
                    row["product"],
                    row["version"],
                    len(row["cves"]),
                    top,
                    theme.risk_label(row["level"]),
                    row["match"] or "-",
                ),
                tags=(row["level"],),
            )

        self.table.bind("<<TreeviewSelect>>", self.show_details)

    def build_details(self):
        label_row = tk.Frame(self, bg=theme.BG)
        label_row.pack(fill="x", pady=(10, 4))
        tk.Label(
            label_row, text="Details  (click a CVE ID to open it on nvd.nist.gov)",
            bg=theme.BG, fg=theme.TEXT, font=(theme.FONT, 10, "bold"),
        ).pack(side="left")
        tk.Label(
            label_row, text="NO MATCH does not prove a service is safe.",
            bg=theme.BG, fg=theme.MUTED, font=(theme.FONT, 9),
        ).pack(side="right")

        frame = tk.Frame(
            self, bg=theme.CARD, highlightbackground=theme.BORDER,
            highlightcolor=theme.BORDER, highlightthickness=1,
        )
        frame.pack(fill="both", expand=True)
        self.details = tk.Text(
            frame, height=5, wrap="word", font=(theme.FONT, 10), bg=theme.CARD,
            relief="flat", borderwidth=0, padx=12, pady=8, state="disabled",
        )
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.details.yview)
        self.details.configure(yscrollcommand=scrollbar.set)
        self.details.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.details.tag_configure("title", font=(theme.FONT, 12, "bold"), spacing3=2)
        self.details.tag_configure("meta", foreground=theme.MUTED)
        self.details.tag_configure("cve", font=(theme.FONT, 10, "bold"), spacing1=8)
        self.details.tag_configure("note", foreground=theme.WARN)
        self.details.tag_configure("muted", foreground=theme.MUTED)
        for level, color in theme.SEVERITY_TEXT.items():
            self.details.tag_configure(f"sev_{level}", foreground=color, font=(theme.FONT, 10, "bold"))

    # ---------- events ----------

    def open_cve(self, cve_id):
        webbrowser.open(NVD_URL + cve_id)

    def export_pdf(self):
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Save report",
            defaultextension=".pdf",
            initialfile=default_filename(self.target, datetime.now()),
            filetypes=[("PDF files", "*.pdf")],
        )
        if not path:
            return  # the person cancelled
        try:
            generate_report(self.target, self.matched, self.info, path)
        except Exception as error:
            messagebox.showerror(
                "Report failed", f"The report could not be created:\n\n{error}"
            )
            return
        if messagebox.askyesno("Report saved", f"Saved to:\n{path}\n\nOpen it now?"):
            self.open_file(path)

    def open_file(self, path):
        if hasattr(os, "startfile"):  # Windows
            os.startfile(path)
        else:
            webbrowser.open(Path(path).resolve().as_uri())

    def show_details(self, event=None):
        selection = self.table.selection()
        if not selection:
            return
        row = self.rows[int(selection[0])]
        box = self.details

        box.config(state="normal")
        box.delete("1.0", "end")
        for tag in box.tag_names():
            if tag.startswith("link_"):
                box.tag_delete(tag)

        title = f"Port {row['port']}  \u00b7  {row['product']} {row['version']}".strip()
        box.insert("end", title + "\n", "title")

        score = row["top_cvss"] if row["top_cvss"] is not None else "-"
        box.insert("end", "Risk: ", "meta")
        box.insert("end", theme.risk_label(row["level"]), f"sev_{row['level']}")
        box.insert(
            "end",
            f"     Top CVSS: {score}     Matched by: {row['match'] or 'nothing'}\n",
            "meta",
        )

        if not row["cves"]:
            box.insert("end", "\nNo matching CVEs were found for this service.\n")
            box.insert(
                "end",
                "This does not prove it is safe. It may mean the exact version could "
                "not be identified, so no match was possible.\n",
                "muted",
            )
        else:
            if row["match"] == LOW_CONFIDENCE:
                box.insert(
                    "end",
                    "\nLow confidence: these CVEs mention the service name, but the exact "
                    "version was not identified, so they may not apply to this device.\n",
                    "note",
                )
            for number, cve in enumerate(row["cves"]):
                cve_score = cve["cvss_score"] if cve["cvss_score"] is not None else "n/a"
                severity = cve["severity"] or "n/a"

                link_tag = f"link_{number}"
                box.tag_configure(link_tag, foreground=theme.ACCENT, underline=True)
                box.tag_bind(link_tag, "<Button-1>",
                             lambda event, cid=cve["cve_id"]: self.open_cve(cid))
                box.tag_bind(link_tag, "<Enter>", lambda event: box.config(cursor="hand2"))
                box.tag_bind(link_tag, "<Leave>", lambda event: box.config(cursor=""))

                box.insert("end", "\n")
                box.insert("end", cve["cve_id"], ("cve", link_tag))
                box.insert("end", "   ", "cve")
                box.insert("end", str(severity), ("cve", f"sev_{severity}"))
                box.insert("end", f"  \u00b7  CVSS {cve_score}\n", "meta")

                description = cve["description"]
                if len(description) > 400:
                    description = description[:400] + "..."
                box.insert("end", description + "\n")

        box.config(state="disabled")