"""
scripts/cpm_pert.py
CPM + PERT for the remaining NVAS work (SE assignment 351 CS 3201, token CC02-P95R-SZ26).

Each task has three-point estimates in hours (optimistic, most likely, pessimistic).
PERT expected time   te = (O + 4M + P) / 6        variance = ((P - O) / 6) ** 2
CPM forward pass     earliest start / finish
CPM backward pass    latest start / finish, total float (float 0 = critical)

Run:  python scripts/cpm_pert.py        (writes docs/diagrams/gantt_remaining_work.png)
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

# id, name, O, M, P, depends_on, tier   (tier: A = do first, B = if time allows)
TASKS = [
    ("T01", "Apply update zip, run tests, commit",             0.5, 1.0, 1.5, [],                          "A"),
    ("T02", "GUI check: scan twice, delta evidence",           1.0, 1.5, 2.5, ["T01"],                     "A"),
    ("T03", "Property 1: pcap of 20 refusals + pytest",        1.0, 2.0, 3.0, ["T01"],                     "A"),
    ("T04", "Property 2: design + ADR (discovery, rate cap)",  0.5, 1.0, 1.5, ["T01"],                     "A"),
    ("T05", "Property 2: throttled scanner at 200 pps",        2.0, 4.0, 6.0, ["T04"],                     "A"),
    ("T06", "Property 2: measure pps and /24 time",            1.0, 2.0, 3.0, ["T05"],                     "A"),
    ("T07", "One-command runner for VS1, VS2, VS3 + README",   1.0, 1.5, 3.0, ["T02", "T05"],              "A"),
    ("T08", "SRS: 20+ requirements + traceability matrix",     1.5, 2.5, 4.0, ["T01"],                     "A"),
    ("T09", "Gherkin 10+ with step definitions",               1.0, 2.0, 3.0, ["T08"],                     "B"),
    ("T10", "ADRs (5+)",                                       1.0, 2.0, 3.0, ["T04"],                     "A"),
    ("T11", "Required diagram set (sources + images)",         3.0, 5.0, 8.0, ["T08"],                     "B"),
    ("T12", "Two hand-drawn diagrams, photographed",           0.5, 1.0, 1.5, [],                          "B"),
    ("T13", "Elicitation: recruit 10 students, print pack",    0.5, 1.0, 2.0, [],                          "A"),
    ("T14", "Elicitation sessions + SUS + affinity grouping",  1.5, 2.5, 4.0, ["T13", "T02"],              "A"),
    ("T15", "Redesign one screen from SUS findings",           1.0, 2.0, 3.0, ["T14"],                     "B"),
    ("T16", "Reconstruct process from git log + challenges",   1.0, 1.5, 2.5, [],                          "A"),
    ("T17", "Control chart + Pareto from git/logbook",         1.0, 1.5, 2.5, ["T16"],                     "B"),
    ("T18", "Risk register 12+, heat map, RMMM top 3",         1.0, 1.5, 2.5, [],                          "A"),
    ("T19", "COCOMO II + Planning Poker + MMRE",               1.0, 1.5, 2.5, [],                          "B"),
    ("T20", "Feasibility: NPV 21%, payback, tornado",          1.0, 1.5, 2.5, [],                          "B"),
    ("T21", "Defect log (5+) incl. git bisect",                1.0, 2.0, 3.0, ["T01"],                     "A"),
    ("T22", "Reliability: 8 test hours + Jelinski-Moranda",    8.0, 8.0, 10.0, ["T07"],                    "B"),
    ("T23", "SAST + Lizard + coverage baseline, triage",       1.0, 1.5, 2.5, ["T07"],                     "A"),
    ("T24", "Reengineer weakest module, before/after",         1.5, 3.0, 5.0, ["T23"],                     "B"),
    ("T25", "40-user load test, p95 <= 1 s",                   1.0, 2.0, 3.0, ["T07"],                     "B"),
    ("T26", "Dossier documents (design, test, QA/SCM, manual)",3.0, 4.0, 6.0, ["T08", "T10", "T18", "T23"], "A"),
    ("T27", "Presentation: update numbers, rehearse 10 min",   0.5, 1.0, 1.5, ["T07", "T23"],             "A"),
    ("T28", "Repo hygiene: rename, README token, CI, tags",    0.5, 1.0, 1.5, ["T01"],                     "A"),
    ("T29", "Release v1.0.0: PDFs, SBOM, SHA-256 list",        1.0, 1.5, 2.5, ["T26", "T23", "T28"],       "A"),
    ("T30", "Proof video (10+ min, unedited)",                 1.0, 1.5, 2.5, ["T29", "T07"],              "A"),
]


def pert(o, m, p):
    return (o + 4 * m + p) / 6, ((p - o) / 6) ** 2


def schedule(tasks):
    info = {}
    for tid, name, o, m, p, deps, tier in tasks:
        te, var = pert(o, m, p)
        info[tid] = dict(id=tid, name=name, te=te, var=var, deps=deps, tier=tier)

    order, seen = [], set()

    def visit(t):
        if t in seen:
            return
        for d in info[t]["deps"]:
            visit(d)
        seen.add(t)
        order.append(t)

    for t in info:
        visit(t)

    for t in order:                                     # forward pass
        es = max((info[d]["ef"] for d in info[t]["deps"]), default=0.0)
        info[t]["es"], info[t]["ef"] = es, es + info[t]["te"]
    end = max(v["ef"] for v in info.values())

    succ = {t: [] for t in info}
    for t, v in info.items():
        for d in v["deps"]:
            succ[d].append(t)
    for t in reversed(order):                           # backward pass
        lf = min((info[s]["ls"] for s in succ[t]), default=end)
        info[t]["lf"], info[t]["ls"] = lf, lf - info[t]["te"]
        info[t]["float"] = round(info[t]["ls"] - info[t]["es"], 6)
        info[t]["critical"] = info[t]["float"] < 1e-6
    return info, order, end


def critical_path(info, order):
    crit = [t for t in order if info[t]["critical"]]
    return sorted(crit, key=lambda t: info[t]["es"])


def gantt(info, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    rows = sorted(info.values(), key=lambda v: (v["es"], v["id"]))
    fig, ax = plt.subplots(figsize=(11, 9))
    for i, v in enumerate(rows):
        colour = "#c0392b" if v["critical"] else ("#1f6f8b" if v["tier"] == "A" else "#8aa7b4")
        ax.barh(i, v["te"], left=v["es"], color=colour, edgecolor="white")
        ax.text(v["es"] + v["te"] + 0.15, i, f'{v["id"]}  {v["name"]}', va="center", fontsize=7)
    ax.set_yticks([])
    ax.invert_yaxis()
    ax.set_xlabel("Hours from start of work (unlimited parallelism, as in classic CPM)")
    ax.set_title("Remaining work: Gantt chart (red = critical path, dark blue = tier A, light = tier B)")
    ax.set_xlim(0, max(v["ef"] for v in rows) + 14)
    ax.grid(axis="x", alpha=0.3)
    fig.text(0.5, 0.01, "351 CS 3201 Software Engineering  |  24311351002 Charles Chima  |  CC02-P95R-SZ26  |  Gantt chart  |  25 Nov 2026",
             ha="center", fontsize=8, color="#555")
    fig.tight_layout(rect=(0, 0.03, 1, 1))
    out = Path("docs/diagrams/gantt_remaining_work.png")
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out, dpi=150)
    return out


def main():
    info, order, end = schedule(TASKS)
    path = critical_path(info, order)
    var = sum(info[t]["var"] for t in path)
    sd = math.sqrt(var)

    print("| ID | Task | Tier | O | M | P | te (h) | Depends on | ES | EF | Float |")
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    raw = {t[0]: t for t in TASKS}
    for t in sorted(info, key=lambda x: (info[x]["es"], x)):
        v, r = info[t], raw[t]
        print(f"| {t} | {v['name']} | {v['tier']} | {r[2]} | {r[3]} | {r[4]} | {v['te']:.2f} | "
              f"{', '.join(v['deps']) or '-'} | {v['es']:.2f} | {v['ef']:.2f} | {v['float']:.2f} |")
    print()
    print("Critical path:", " -> ".join(path))
    print(f"Project duration (CPM, unlimited parallelism): {end:.2f} h; PERT std dev {sd:.2f} h; "
          f"95% bound about {end + 1.645 * sd:.1f} h")
    total = sum(v["te"] for v in info.values())
    a = sum(v["te"] for v in info.values() if v["tier"] == "A")
    print(f"Total effort: {total:.1f} h  (tier A {a:.1f} h, tier B {total - a:.1f} h)")
    print("Wrote", gantt(info, path))


if __name__ == "__main__":
    sys.exit(main())
