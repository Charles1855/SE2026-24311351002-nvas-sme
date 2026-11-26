# NVAS final plan: schedule, processes, checklist, commits and tags
Charles Chima, 24311351002, token CC02-P95R-SZ26. Prepared Wed 25 Nov 2026 for submission Thu 26 Nov 2026

---

## 0. Read this first

The card asks for about **66 hours of work**. Even with unlimited parallel help the **critical path is 16.6 hours**. You have roughly **19 working hours** left, so this plan does not try to do everything. It does the items that make the system and the evidence real first, and it lists honestly what will not be finished.

Two things to do today that can change the picture:
1. **Ask the lecturer for a short extension now**, with evidence of progress (repo history, 113 tests, three of the four properties working). A short, honest email is better than a rushed, thin submission. Something like: *"Dear Sir/Madam, I am registration 24311351002. My assignment is due 26 Nov. I have completed [x, y, z] and have evidence in the repository, but the card's scope (about 65 hours of tasks) will not fit in the remaining time. May I have an extension to [date] to finish [the remaining items]? Charles Chima."*
2. **Assume the deadline is the end of 26 Nov** unless the lecturer says otherwise. If it is earlier, cut from the bottom of the schedule in section 1.

---

## 1. Schedule for the next 24 hours (Central Africa Time)

This is the single-person timetable you actually follow. The CPM network in section 2 is the formal plan for the card's simulated team.

**Wednesday 25 Nov**

| Time | Task | Hours | You are finished when |
|---|---|---|---|
| 12:00 to 13:00 | **T01** Apply the complete zip | 1.0 | Characterisation tests committed first, then the files copied over, `report_generator.py` one-liner done, `pytest` green, commits 1 to 10 made |
| 13:00 to 13:30 | **T13** Lunch, and confirm 10 classmates for the sessions | 0.5 | 10 names confirmed, forms printed |
| 13:30 to 14:30 | **T28** Repo hygiene | 1.0 | `git tag -n` checked, README token header, repo renamed, lecturer and TA added, CI green screenshot |
| 14:30 to 16:00 | **T02** Check the GUI end to end | 1.5 | Two scans of Metasploitable2 with one service changed between them; screenshot of the delta log line and the report in `reports\` |
| 16:00 to 18:30 | **T14** Elicitation sessions (2 groups of 5) + SUS | 2.5 | Signed consents, register, completed questionnaires, photos of notes (see the elicitation pack) |
| 18:30 to 19:30 | Break | 1.0 | |
| 19:30 to 21:30 | **T03** Property 1 evidence | 2.0 | tshark capture with zero packets for 20 refusals, plus a pytest of the 20 attempts |
| 21:30 to 23:00 | Documents with Claude drafting, you reviewing: **T08** SRS, **T18** risk register, **T10** first ADRs | 1.5 | Draft files committed |
| 23:00 to 07:00 | Sleep | | |

**Thursday 26 Nov**

| Time | Task | Hours | You are finished when |
|---|---|---|---|
| 07:00 to 09:00 | **T04 + T05** Property 2 design and code | 2.0 | ADR written; host discovery first, then port scan capped at 200 packets/s (nmap `--max-rate 200`) |
| 09:00 to 10:30 | **T06** Property 2 measurement | 1.5 | Packet capture shows 200 pps or less; scan time of the live hosts measured; the /24 estimate is calculated in the report |
| 10:30 to 11:30 | **T07** One-command runner for VS1, VS2, VS3 | 1.0 | One documented command in the README runs all three slices |
| 11:30 to 12:30 | **T23 + T21** Quality numbers and defect log | 1.0 | pytest-cov, Lizard and SAST results; at least 5 real defects logged |
| 12:30 to 13:30 | Lunch | 1.0 | |
| 13:30 to 14:30 | **T26** Minimum dossier files | 1.0 | Logbook entries, `reflection.md`, `ai-disclosure.md`, baseline report |
| 14:30 to 15:30 | **T29** Tags and release | 1.0 | Tags only for stages whose criteria are really met (section 6); PDFs, SBOM, SHA-256 list; GitHub Release |
| 15:30 to 17:00 | **T30** Proof video | 1.5 | One unedited recording of 10+ minutes |
| 17:00 to 18:00 | **T27** Presentation numbers, one rehearsal, submit | 1.0 | Slides updated with final numbers; submitted |

**Not in this schedule (declare them honestly as not completed, or ask for the extension):**
T09 Gherkin step definitions · T11 full diagram set (only the Gantt chart exists) · T12 hand-drawn diagrams · T15 screen redesign · T17 control chart and Pareto · T19 COCOMO II and Planning Poker · T20 NPV and tornado · T22 8-hour reliability campaign · T24 reengineering · T25 40-user load test.

Several of these are mostly writing, and I can draft them in this chat for you to review (you must declare that in `docs/ai-disclosure.md`): SRS, Gherkin, ADRs, Mermaid diagram sources, risk register, COCOMO II, NPV. The ones that need your real data (control chart, Pareto, Planning Poker, SUS scores) need numbers from you first.

---

## 2. WBS, PERT and critical path (computed by `scripts/cpm_pert.py`)

Estimates are three-point (optimistic, most likely, pessimistic) in hours. PERT expected time = (O + 4M + P) / 6. ES/EF are earliest start and finish, assuming unlimited parallel workers as in classic CPM. Tier A is done first and tier B only if time allows.

| ID | Task | Tier | O | M | P | te (h) | Depends on | ES | EF | Float |
|---|---|---|---|---|---|---|---|---|---|---|
| T01 | Apply update zip, run tests, commit | A | 0.5 | 1.0 | 1.5 | 1.00 | - | 0.00 | 1.00 | 0.00 |
| T12 | Two hand-drawn diagrams, photographed | B | 0.5 | 1.0 | 1.5 | 1.00 | - | 0.00 | 1.00 | 15.58 |
| T13 | Elicitation: recruit 10 students, print pack | A | 0.5 | 1.0 | 2.0 | 1.08 | - | 0.00 | 1.08 | 10.92 |
| T16 | Reconstruct process from git log + challenges | A | 1.0 | 1.5 | 2.5 | 1.58 | - | 0.00 | 1.58 | 13.42 |
| T18 | Risk register 12+, heat map, RMMM top 3 | A | 1.0 | 1.5 | 2.5 | 1.58 | - | 0.00 | 1.58 | 7.67 |
| T19 | COCOMO II + Planning Poker + MMRE | B | 1.0 | 1.5 | 2.5 | 1.58 | - | 0.00 | 1.58 | 15.00 |
| T20 | Feasibility: NPV 21%, payback, tornado | B | 1.0 | 1.5 | 2.5 | 1.58 | - | 0.00 | 1.58 | 15.00 |
| T02 | GUI check: scan twice, delta evidence | A | 1.0 | 1.5 | 2.5 | 1.58 | T01 | 1.00 | 2.58 | 3.42 |
| T03 | Property 1: pcap of 20 refusals + pytest | A | 1.0 | 2.0 | 3.0 | 2.00 | T01 | 1.00 | 3.00 | 13.58 |
| T04 | Property 2: design + ADR (discovery, rate cap) | A | 0.5 | 1.0 | 1.5 | 1.00 | T01 | 1.00 | 2.00 | 0.00 |
| T08 | SRS: 20+ requirements + traceability matrix | A | 1.5 | 2.5 | 4.0 | 2.58 | T01 | 1.00 | 3.58 | 5.67 |
| T21 | Defect log (5+) incl. git bisect | A | 1.0 | 2.0 | 3.0 | 2.00 | T01 | 1.00 | 3.00 | 13.58 |
| T28 | Repo hygiene: rename, README token, CI, tags | A | 0.5 | 1.0 | 1.5 | 1.00 | T01 | 1.00 | 2.00 | 11.42 |
| T17 | Control chart + Pareto from git/logbook | B | 1.0 | 1.5 | 2.5 | 1.58 | T16 | 1.58 | 3.17 | 13.42 |
| T05 | Property 2: throttled scanner at 200 pps | A | 2.0 | 4.0 | 6.0 | 4.00 | T04 | 2.00 | 6.00 | 0.00 |
| T10 | ADRs (5+) | A | 1.0 | 2.0 | 3.0 | 2.00 | T04 | 2.00 | 4.00 | 5.25 |
| T14 | Elicitation sessions + SUS + affinity grouping | A | 1.5 | 2.5 | 4.0 | 2.58 | T13, T02 | 2.58 | 5.17 | 9.42 |
| T09 | Gherkin 10+ with step definitions | B | 1.0 | 2.0 | 3.0 | 2.00 | T08 | 3.58 | 5.58 | 11.00 |
| T11 | Required diagram set (sources + images) | B | 3.0 | 5.0 | 8.0 | 5.17 | T08 | 3.58 | 8.75 | 7.83 |
| T15 | Redesign one screen from SUS findings | B | 1.0 | 2.0 | 3.0 | 2.00 | T14 | 5.17 | 7.17 | 9.42 |
| T06 | Property 2: measure pps and /24 time | A | 1.0 | 2.0 | 3.0 | 2.00 | T05 | 6.00 | 8.00 | 8.58 |
| T07 | One-command runner for VS1, VS2, VS3 + README | A | 1.0 | 1.5 | 3.0 | 1.67 | T02, T05 | 6.00 | 7.67 | 0.00 |
| T22 | Reliability: 8 test hours + Jelinski-Moranda | B | 8.0 | 8.0 | 10.0 | 8.33 | T07 | 7.67 | 16.00 | 0.58 |
| T23 | SAST + Lizard + coverage baseline, triage | A | 1.0 | 1.5 | 2.5 | 1.58 | T07 | 7.67 | 9.25 | 0.00 |
| T25 | 40-user load test, p95 <= 1 s | B | 1.0 | 2.0 | 3.0 | 2.00 | T07 | 7.67 | 9.67 | 6.92 |
| T24 | Reengineer weakest module, before/after | B | 1.5 | 3.0 | 5.0 | 3.08 | T23 | 9.25 | 12.33 | 4.25 |
| T26 | Dossier documents (design, test, QA/SCM, manual) | A | 3.0 | 4.0 | 6.0 | 4.17 | T08, T10, T18, T23 | 9.25 | 13.42 | 0.00 |
| T27 | Presentation: update numbers, rehearse 10 min | A | 0.5 | 1.0 | 1.5 | 1.00 | T07, T23 | 9.25 | 10.25 | 6.33 |
| T29 | Release v1.0.0: PDFs, SBOM, SHA-256 list | A | 1.0 | 1.5 | 2.5 | 1.58 | T26, T23, T28 | 13.42 | 15.00 | 0.00 |
| T30 | Proof video (10+ min, unedited) | A | 1.0 | 1.5 | 2.5 | 1.58 | T29, T07 | 15.00 | 16.58 | 0.00 |

**Critical path:** T01 -> T04 -> T05 -> T07 -> T23 -> T26 -> T29 -> T30  
**Project duration (CPM, unlimited parallelism):** 16.58 h; PERT std dev 1.02 h; 95% bound about 18.3 h  
**Total effort:** 65.9 h  (tier A 37.6 h, tier B 28.3 h)  

The critical path is **T01 → T04 → T05 → T07 → T23 → T26 → T29 → T30**. Property 2 (T04, T05) sits on it, which is why it is the riskiest task. T22 (8 test hours) has only 0.58 h of float.

Regenerate the table and chart with `python scripts/cpm_pert.py`. It writes `docs/diagrams/gantt_remaining_work.png`, with your token and registration number in the footer as the card requires. Check the numbers by hand for the defense (the card asks you to recompute a float). Not done yet from the scheduling requirement: daily CPI/SPI and the RACI matrix.

---

## 3. Processes found and processes used

**Found (reconstruct from your commit history, as the card asks).** These come from how you described the project, so check them against your `git log` before you present them:
- **Incremental, phased delivery** on a 16-week roadmap with weekly milestones: CLI scanner, then CVE matching with SQLite, then the Tkinter GUI, then reporting and testing.
- **Module-by-module validation** with standalone test files before integration (for example `test_vuln_matcher.py`).
- **Conventional commit prefixes:** `feat:` only for validated work, `wip:` for in-progress work, plus `chore:`, `fix:`, `test:`.
- **Supervisor review checkpoints** during the mini project.

**Comparison with the assigned models:** Incremental fits best, because each module was built, validated and then integrated. It is not Waterfall, because requirements, design and testing were not done as separate whole-project phases. It has some Spiral character (choosing the Metasploitable2 VM for repeatable CVEs was a risk decision), but there were no formal risk-driven iterations. Scrum was not used before this assignment.

**Prove it with numbers (PowerShell, run in the repo):**
```
git log --format=%ad --date=short | Group-Object | Sort-Object Name | Select-Object Name,Count
git log --format=%s | ForEach-Object { if ($_ -match '^(\w+):') { $Matches[1] } else { 'other' } } | Group-Object | Sort-Object Count -Descending | Select-Object Name,Count
```
The first gives commits per day (needed for the 8-day and 25% rules and the control chart). The second gives commits by type (feat, fix, test, wip) for the rework and defect measurement.

**Used during this assignment (what we actually did):**
| Process | Where it shows |
|---|---|
| Characterisation-first change | 20 tests written against the unchanged `risk_scorer.py` before it was modified |
| Incremental integration | Standalone modules first, then the adapter, then the GUI hook, then the ranking change |
| Test-after for new modules, with tests in the same commit group | Honest note: this was not strict BDD. The Gherkin scenarios were written as feature files only |
| Measure-then-fix quality gates | pytest-cov, then Lizard found 2 over-long new functions, which were split |
| Risk-driven design change | A failed NVD lookup could report a finding as "fixed", so such scans are not recorded for comparison |
| Maintenance classification (ISO/IEC 14764) | Table in `NVAS_properties_3_4_notes.md` |
| Traceability | Requirement to code to test for FR-S3, FR-S4, FR-S5 |
| AI-assisted drafting with human review | To be declared in `docs/ai-disclosure.md` |

**CMMI areas assigned:** *Risk Management (RSKM):* risk register, mitigations (the failed-lookup guard), and a cut list for the deadline. *Process and Product Quality Assurance (PPQA):* objective evaluation with tools (coverage, Lizard, SAST), commit conventions, and quality gates.

**Process for the remaining work: Scrum with two short sprints.** Sprint 1 (24 to 25 Nov): properties 3 and 4, integration, evidence. Sprint 2 (25 to 26 Nov): properties 1 and 2, one-command runner, documents, release. The sprint backlog is the tier A list. Each working session's logbook entry is the daily scrum. Be honest in the retrospective that the sprints were compressed to hours because of the deadline.

**Challenge register (8 or more, all real events):**
| # | Challenge | What happened or what was done |
|---|---|---|
| 1 | `.gitignore` saved as UTF-16 | Git silently ignored the patterns; re-saved as UTF-8 |
| 2 | NVD CVSS v2 severity sits beside `cvssData` | Parsed the v2 branch separately |
| 3 | Metasploitable2 VM deleted by mistake on 20 Nov | Re-created; the IP changed to 192.168.56.102 (DHCP) |
| 4 | Asset criticality is keyed by IP | A changed IP silently falls back to the default level |
| 5 | Two rankings (plain CVSS and criticality-weighted) could disagree | `rank_findings` now applies criticality so screen and PDF agree |
| 6 | NVD timeouts would show as "fixed" in the delta | Scans with failed lookups are not recorded for comparison |
| 7 | Challenge says CVSS v3.1 but NVD sometimes has only v2 | CVSS version carried through and fallbacks labelled |
| 8 | Windows CRLF line endings | Patched files kept CRLF so git shows only real changes |
| 9 | Duplicate `report_generator.py` in `gui/` and `analysis/` | The app imports `analysis.report_generator`; the other looks like a leftover |
| 10 | 254 hosts x 1,000 ports at 200 pps takes about 21 min | Needs host discovery first so only live hosts are port scanned |
| 11 | The card's workload against one day | Triage plan and extension request (this document) |

---

## 4. Checklist from your screenshots, with status

Status key: **Done**, **Drafted** (Claude drafted it; you review and commit), **Partial**, **Not started**, **Needs people**, **Check** (I cannot see it).

**Requirements table**

| Topic | Status | What exists or what is missing |
|---|---|---|
| Software characterisation | Not started | Classify NVAS as a security tool; failure-rate curve vs a network switch |
| Crisis and ethics | Not started | Equifax fishbone; one-page ethics analysis against the ACM/IEEE-CS code and the Malawi Data Protection Act |
| Process | Drafted | Section 3. Verify against `git log`; challenge register has 11 items |
| Process measurement | Not started | Needs the git-log commands above; control chart and Pareto by script |
| Feasibility | Not started | Cost to date vs MWK 9,800,000; NPV at 21%; payback; tornado |
| Elicitation | Drafted, needs people | Pack is ready; 10 students must attend and sign |
| Analysis (context, DFD 0 to 1, ERD, quality-attribute scenarios) | Not started | ERD gains 4 tables (`scan_runs`, `scan_hosts`, `scan_findings`, `finding_registry`) |
| SRS and traceability | Partial | FR-S3, FR-S4, FR-S5 drafted; 17 more needed; 7 Gherkin scenarios drafted (10 needed) |
| Architecture and data | Not started | At least 5 ADRs covering scope, throttling and the plug-in model; 2 extra drafted (risk formula, evidence hash) |
| Component and UI design | Partial | Scoring pseudocode and decision table done; SUS test and a redesigned screen not done |
| Patterns, reviews and coding | Not started | Template Method, Observer, Factory Method; one structured walkthrough; SAST triage |
| Working increments (VS1, VS2, VS3) | Partial | VS2 and VS3 built and wired; VS1 partly (scope guard exists); one-command runner not built |
| Testing the as-built code | Partial | 20 characterisation tests done; baseline coverage, complexity and defect counts at v0.7 not recorded |
| Test design and levels | Partial | CVSS band boundary tests done; equivalence classes for targets, pairwise tests, control-flow graph, 40-user load test, UAT form not done |
| Debugging and maintenance | Partial | Maintenance-type table drafted; 5 real defects, `git bisect`, Drop 3 fix not done |
| Planning and estimation | Partial | This plan; COCOMO II and Planning Poker not done |
| Scheduling and staffing | Partial | WBS (30 tasks), CPM/PERT script and Gantt done; daily CPI/SPI and RACI not done |
| Risk and quality | Partial | 5 risks drafted (12 needed); heat map, RMMM and technical-debt measures not done |
| Reliability, SCM, reengineering | Not started | Jelinski-Moranda on 8 test hours; SCM plan and SBOM; reengineered module |

**Deliverables table**

| Deliverable | Status | Note |
|---|---|---|
| Project repository (renamed, history intact, main protected, CI green) | Check | Rename to `SE2026-24311351002-nvas-sme`; do not squash or rewrite history |
| As-built baseline report (`docs/00-baseline/`) | Partial | Gap-list rows for properties 3 and 4 drafted; inventory and v0.7 metrics not done |
| Engineering logbook (`docs/logbook/`) | Check | One dated entry per working session; 24 and 25 Nov entries are needed |
| Elicitation evidence pack | Drafted, needs people | Register, consent slips, notes, transcripts |
| Dossier documents | Not started | SRS, design, test plan and report, project plan, QA/SCM, maintenance report |
| Working system | Partial | Three slices must run from one command on a clean clone |
| Diagrams (`docs/diagrams/`) | Partial | Gantt done; 16 more required plus 2 hand-drawn |
| User documentation | Not started | Manual for SME IT officers and a short runbook |
| Release package (v1.0.0) | Not started | PDFs, SBOM, SHA-256 list |
| Proof video | Not started | 10+ minutes, unedited, visible clock and token |
| Presentation | Drafted | `NVAS_Presentation.pptx`, 12 slides; update numbers before presenting |
| Reflection and AI disclosure | Drafted | AI disclosure text exists in the notes; `reflection.md` not written |

---

## 5. Elicitation (summary; the printable pack has the full forms)

- **Who:** at least 10 fellow students, each playing one assigned role: SME owner, part-time IT officer, managed-service technician, MACRA compliance officer. Suggested split: 3, 3, 2, 2.
- **When and how:** two sessions of 5 students, about 60 minutes each: 10 minutes consent and briefing, 10 minutes live demo, 20 minutes structured interviews, 10 minutes questionnaire, 10 minutes SUS.
- **Techniques (assigned):** structured interviews, questionnaires, and observation of one student role-playing an IT officer running a scan.
- **Safety and ethics:** the demo scans only your Metasploitable2 VM, which is inside the signed scope. No real organisation's data is used. Participation is voluntary and every participant signs a consent slip.
- **Outputs:** participant register (name, registration number, role, date, signature), signed consent slips, photos of notes, transcripts, and an affinity grouping of gaps and conflicts.
- **Integrity:** every participant on the register can be asked to confirm the session, so it must really happen.

---

## 6. Commits

**Already prepared (code, in this order):**
```
test: add 20 characterisation tests for as-built risk_scorer
feat: add reproducible CVSS and asset-criticality risk prioritisation with CVE de-duplication
feat: store ranked findings per scan run with a de-duplicated finding registry
feat: add delta report (new, fixed, persisting) with SHA-256 evidence hashes
feat: add delta_tool CLI (demo, rank, ingest, delta, latest)
feat: connect matcher output to prioritisation and delta through scan_integration
feat: pass CVSS version through the NVD matcher and count failed lookups
feat: apply asset criticality in rank_findings so screen and PDF agree
feat: record findings and compare with the previous scan after each scan
fix: pass the scan target to rank_findings so the results screen and PDF use asset criticality
```
The exact `git add` command for each is in `NVAS_properties_3_4_notes.md`. The earlier docs commit is replaced by the ones below.

**New documents (make each one a separate commit; every path below is a file in the package):**
```
git add scripts/cpm_pert.py
git commit -m "chore: add CPM and PERT script for the remaining work"

git add docs/diagrams/gantt_remaining_work.png docs/project-plan.md
git commit -m "docs: add project plan with WBS, critical path, Gantt chart, process and checklist"

git add docs/signature-challenge-notes.md
git commit -m "docs: add gap list, scoring specification, Gherkin scenarios and defense questions for properties 3 and 4"

git add docs/test-inventory.md
git commit -m "docs: add test inventory for properties 3 and 4"

git add docs/elicitation/NVAS_Elicitation_Pack.pdf
git commit -m "docs: add elicitation protocol, questionnaires, SUS form and consent slip"

git add docs/presentation/NVAS_Presentation.pptx
git commit -m "docs: add 12-slide presentation"

git add docs/logbook/2026-11-25.md
git commit -m "docs: add logbook entry for 25 Nov"
```
The elicitation PDF is exported from the document `NVAS Elicitation Pack` (download as PDF). `docs/signature-challenge-notes.md` is the file `NVAS_properties_3_4_notes.md` renamed, and `docs/test-inventory.md` is `NVAS_test_inventory.md` renamed. Later, copy the gap-list rows from the notes into `docs/00-baseline/` when you write the baseline report.

The elicitation evidence (signed slips, photos) goes in `docs/elicitation/evidence/` as a separate commit after the sessions: `docs: add signed participant register and consent slips`.

**Integrity rules:** the card needs commits on at least 8 distinct days with no single day over 25% of all commits. With history since July you probably meet this, but check with the first PowerShell command in section 3 before you submit. Never use `--date`, rebase or squash to change it.

---

## 7. Tags

Tag order from the card: **v0.7-asbuilt, v0.8, v0.9, v0.95, v1.0.0, v1.0.1**. Tag a stage only when its criteria are really met. A tag you cannot justify in the defense is worse than a missing one, and then you declare what was not reached.

| Tag | Meaning | Create it when |
|---|---|---|
| `v0.7-asbuilt` | Code before any dossier work | Check first: `git tag -n`. If it already exists, do not move it. If it does not, tag the last commit before the dossier work started, not today's HEAD |
| `v0.8` | Requirements baseline | SRS with 20+ requirements tagged Built/Partial/New, 10+ Gherkin tests and the traceability matrix are committed |
| `v0.9` | Design baseline with all three slices running | VS1, VS2 and VS3 run from the one documented command. Do not tag this if they do not |
| `v0.95` | Tests and management documents | Test plan and report, project plan, risk register, QA and SCM notes are committed |
| `v1.0.0` | Release | Dossier PDFs, SBOM and checksum list exist and the proof video is made |
| `v1.0.1` | After Drop 3 | Only after the lecturer's legacy code package is fixed |

**Commands (PowerShell):**
```
git tag -n                                  # see what exists
git log --oneline --decorate -20            # find the right commit for v0.7-asbuilt if it is missing

# only if v0.7-asbuilt does not exist; replace <commit> with the real baseline commit
git tag -a v0.7-asbuilt <commit> -m "v0.7-asbuilt: as-built baseline before dossier work. Token CC02-P95R-SZ26"

# later tags, on the current commit, each with the token in the message
git tag -a v0.8 -m "v0.8: requirements baseline. CC02-P95R-SZ26"
git tag -a v0.9 -m "v0.9: design baseline, three slices running. CC02-P95R-SZ26"
git tag -a v0.95 -m "v0.95: tests and management documents. CC02-P95R-SZ26"
git tag -a v1.0.0 -m "v1.0.0: submission release. CC02-P95R-SZ26"
git push origin --tags
```
Do not delete or move a tag after you push it.

**Release package for v1.0.0 (PowerShell):**
```
# SBOM (CycloneDX, JSON)
pip install cyclonedx-bom
cyclonedx-py requirements requirements.txt --of JSON -o docs\sbom.json

# SHA-256 list for the release files
Get-ChildItem docs\*.pdf, docs\sbom.json | Get-FileHash -Algorithm SHA256 |
  ForEach-Object { "$($_.Hash.ToLower())  $(Split-Path $_.Path -Leaf)" } |
  Out-File docs\checksums-sha256.txt -Encoding ascii
```
Then on GitHub: **Releases, Draft a new release**, choose tag `v1.0.0`, attach the PDFs, `sbom.json` and `checksums-sha256.txt`, and publish. (With the GitHub CLI you can use `gh release create v1.0.0 <files> --title "v1.0.0" --notes "..."`.) Export each dossier document to PDF first.

---

## 8. What I need from you next

1. The output of the two PowerShell commands in section 3 (commits per day and per type). With that I can write the process reconstruction with real numbers and script the control chart and Pareto.
2. Tell me which documents to draft next: SRS, Gherkin, ADRs, Mermaid diagram sources, risk register, COCOMO II, NPV. Your inputs matter for COCOMO II (lines of code, from `cloc` or `lizard`) and NPV (costs and revenue assumptions).
3. After the sessions, the participant details (names, registration numbers, roles) and the SUS answers so I can compute the scores and the affinity grouping.
