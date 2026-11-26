# NVAS: Signature Challenge properties 3 and 4
**What we built, the commit messages, and how to explain it**
Charles Chima, 24311351002 · token CC02-P95R-SZ26 · prepared 24 Nov 2026

Properties 3 (risk prioritisation) and 4 (delta reporting) are built, tested and wired into the scan flow. Property 1 still needs its packet-capture evidence and an automated test, and property 2 (throttling) is not started. Section 9 lists what is still open.

---

## 1. Numbers you can quote (measured in the sandbox, re-run them on your machine)

| Measure | Result | Card target |
|---|---|---|
| Tests in the files delivered | 113 pass | 60+ in total |
| Characterisation tests on as-built `risk_scorer.py` | 20, all pass on the UNCHANGED code | 20+ |
| Coverage of new modules (prioritiser, delta, scan_integration, findings_store) | 97% (line + branch) | new code 80% line, 70% branch |
| Lizard on new code | no function over CC 10 or 40 lines | CC 10 or less, 40 lines or less |

Re-run on your machine:
```
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pytest -q --cov=analysis.prioritiser --cov=analysis.delta --cov=analysis.scan_integration --cov=database.findings_store --cov-branch
.\.venv\Scripts\python.exe -m lizard analysis database delta_tool.py -C 10 -L 40 -w
```
(`pip install pytest-cov lizard` first.) Lizard will also list some of your as-built functions (for example `ScanView.__init__`). Only code written after v0.7-asbuilt has to meet the limits. Screenshot each run for the dossier.

---

## 2. Commit messages, in the order to make them

Use your own convention (`feat:` only for validated work). Commit with explicit paths, not `git add .`, so each commit holds only its own files.

**Commit 1: do this BEFORE you replace `risk_scorer.py`.** The tests pass against your unchanged code, which proves they describe the as-built behaviour.
```
git add tests/test_characterise_risk_scorer.py
git commit -m "test: add 20 characterisation tests for as-built risk_scorer"
```

```
git add analysis/prioritiser.py config/asset_criticality.json tests/conftest.py tests/test_prioritiser.py
git commit -m "feat: add reproducible CVSS and asset-criticality risk prioritisation with CVE de-duplication"

git add database/findings_store.py
git commit -m "feat: store ranked findings per scan run with a de-duplicated finding registry"

git add analysis/delta.py tests/test_delta.py
git commit -m "feat: add delta report (new, fixed, persisting) with SHA-256 evidence hashes"

git add delta_tool.py
git commit -m "feat: add delta_tool CLI (demo, rank, ingest, delta, latest)"

git add analysis/scan_integration.py tests/test_scan_integration.py
git commit -m "feat: connect matcher output to prioritisation and delta through scan_integration"

git add analysis/vuln_matcher.py tests/test_matcher_failures.py
git commit -m "feat: pass CVSS version through the NVD matcher and count failed lookups"

git add analysis/risk_scorer.py tests/test_rank_findings_criticality.py
git commit -m "feat: apply asset criticality in rank_findings so screen and PDF agree"

git add gui/scan_view.py
git commit -m "feat: record findings and compare with the previous scan after each scan"

git add gui/results_view.py analysis/report_generator.py
git commit -m "fix: pass the scan target to rank_findings so the results screen and PDF use asset criticality"

git add docs/
git commit -m "docs: add logbook entry and AI disclosure for risk prioritisation and delta reporting"
```
Run `python -m pytest -q` before each commit. If one fails, fix it in that commit.

**Integrity rules from the card. Check them now:**
```
git log --format=%ad --date=short | Group-Object | Sort-Object Name | Select-Object Name,Count
```
You need commits on at least 8 distinct days, and no single day may hold more than 25% of all commits. Today is already a heavy day. Do NOT fix this with `--date`, rebasing or squashing. The card treats rewriting history as a breach. Make small honest commits over the remaining days instead.

---

## 3. Gap analysis rows (for `docs/00-baseline/`)

| Property | As-built at v0.7 | Gap | Now | Evidence |
|---|---|---|---|---|
| 3 Risk prioritisation | `risk_scorer.py` ranks one row per service by max CVSS, with deterministic tie-breaks. No asset criticality. Every scan inserts new rows, so a rescan duplicates CVEs. | No criticality in the score. No CVE de-duplication across rescans. CVSS version not tracked. | Score = CVSS x criticality multiplier (capped at 10). A fixed tie-break chain gives a reproducible order. One registry row per finding across scans. The CVSS version is carried and fallbacks are labelled. | `analysis/prioritiser.py`, `database/findings_store.py`; `test_prioritiser.py`, `test_rank_findings_criticality.py`, `test_characterise_risk_scorer.py` |
| 4 Delta reporting | Nothing. Scans are stored per port with no link between runs. | No run identity, no comparison, no evidence hash, no report. | `scan_runs` table; delta of NEW / FIXED / PERSISTING per target; SHA-256 evidence hash on every finding; JSON + Markdown report written on each rescan. | `analysis/delta.py`, `analysis/scan_integration.py`; `test_delta.py`, `test_scan_integration.py` |

---

## 4. Where this fits in the assignment deliverables

| Card requirement | Use from this work |
|---|---|
| Gap list / baseline report | Section 3 |
| SRS: 3 functional requirements for the Signature Challenge | See FR-S3 and FR-S4 below (tag them New) |
| Gherkin tests (10 or more) | Section 7 gives 7 scenarios |
| Traceability matrix (requirement to code to test) | FR-S3 -> `prioritiser.py` -> `test_prioritiser.py`; FR-S4 -> `delta.py` -> `test_delta.py` |
| Component design: risk-scoring engine with pseudocode and a decision table | Section 5 |
| Boundary tests on CVSS bands (3.9/4.0, 6.9/7.0, 8.9/9.0) | `test_characterise_risk_scorer.py::test_score_to_level_boundaries` |
| 20+ characterisation tests before changing anything | 20 tests, commit 1 |
| Required diagrams: finding state diagram, DFD process 4.0, sequence "rescan producing a delta report", ERD | State diagram = `finding_registry.status` (open -> fixed -> open again if it reappears). ERD gains `scan_runs`, `scan_hosts`, `scan_findings`, `finding_registry`. |
| ISO 25010: fault tolerance | The failed-lookup guard (section 8, risk R-1) |
| Maintenance classification of each change since v0.7 | Table below |
| ADRs | Two extra ADRs worth writing: (a) risk = CVSS x criticality multiplier; (b) finding fingerprint and evidence hash |
| Release package | Put `reports/delta_scan1_to_scan2.md` (a real one from the VM) in `docs/` |

**Proposed requirements (adjust the IDs to your SRS):**
- **FR-S3 (New).** The system shall rank findings by risk score = CVSS base score x asset-criticality multiplier (cap 10), produce the same order for the same input in any input order, and keep one record per (host, port, protocol, CVE) across rescans.
- **FR-S4 (New).** After a rescan of a target, the system shall produce a report listing new, fixed and persisting findings, each with a SHA-256 evidence hash.
- **FR-S5 (New).** The system shall not compare a scan whose CVE lookups failed, because missing data would be reported as fixed.

**Maintenance types (ISO/IEC 14764) for the commits:**

| Commit | Type |
|---|---|
| prioritiser, findings store, delta, delta_tool, scan_integration | Perfective (new capability required by the Signature Challenge) |
| risk_scorer criticality, scan_view hook | Perfective |
| matcher CVSS version | Perfective |
| failed-lookup counter and guard | Corrective / preventive (stops false "fixed") |
| results_view / report_generator target argument | Corrective (keeps screen and PDF consistent) |
| splitting `normalise_finding` and `save_scan` into helpers | Preventive (refactoring for the CC/length gates) |

---

## 5. Risk-scoring engine: specification

**Pseudocode**
```
FUNCTION prioritise(rows, criticality_table):
    best = empty map                                   # fingerprint -> finding
    FOR each row IN rows:
        finding = normalise(row)                       # None if no CVE; error if host/port missing or CVSS not in 0..10
        IF finding is None: CONTINUE
        fingerprint = SHA256(host | port | protocol | CVE_ID)
        IF fingerprint not in best OR finding wins tie-break: best[fingerprint] = finding
            # tie-break = higher CVSS, then evidence hash, then description
    FOR each finding IN best:
        level = criticality_table[host] OR criticality_table["default"] OR 3
        raw   = ROUND(cvss * multiplier[level], 2)     # 1:0.8 2:0.9 3:1.0 4:1.1 5:1.2
        risk  = MIN(10.0, raw)
        band  = CRITICAL if risk>=9 ; HIGH if >=7 ; MEDIUM if >=4 ; LOW if >0 ; else INFO
    SORT by (-raw, -cvss, host as number, port, protocol, CVE_ID)
    assign rank 1..n
    RETURN findings
```

**Decision table (risk score and band by CVSS and asset criticality)**

| CVSS base | crit 1 (x0.8) | crit 2 (x0.9) | crit 3 (x1.0) | crit 4 (x1.1) | crit 5 (x1.2) |
|---|---|---|---|---|---|
| 9.8 | 7.84 HIGH | 8.82 HIGH | 9.8 CRITICAL | 10 CRITICAL | 10 CRITICAL |
| 7.5 | 6 MEDIUM | 6.75 MEDIUM | 7.5 HIGH | 8.25 HIGH | 9 CRITICAL |
| 5.0 | 4 MEDIUM | 4.5 MEDIUM | 5 MEDIUM | 5.5 MEDIUM | 6 MEDIUM |
| 4.0 | 3.2 LOW | 3.6 LOW | 4 MEDIUM | 4.4 MEDIUM | 4.8 MEDIUM |
| 3.9 | 3.12 LOW | 3.51 LOW | 3.9 LOW | 4.29 MEDIUM | 4.68 MEDIUM |
| 2.0 | 1.6 LOW | 1.8 LOW | 2 LOW | 2.2 LOW | 2.4 LOW |

Read it this way: a 9.8 on the least important asset is still HIGH (7.84), and a 7.5 on the most important asset becomes CRITICAL (9.0). A 4.0 on a criticality-1 asset drops to LOW (3.2).

**Why the cap uses `raw` for sorting:** capping at 10 keeps the 0 to 10 scale and the existing band thresholds. If we sorted on the capped value, many findings would tie at 10.0. Sorting on `raw` keeps their order.

---

## 6. Live demonstration script (properties 3 and 4)

1. Show the tests passing: `python -m pytest -q`.
2. Run `python delta_tool.py demo`. It shows the ranking, "Reproducible: True", one registry row per finding, and a delta report. Point out that the sample data is labelled as a demo.
3. In the app, scan Metasploitable2 (first scan). The log says: "First recorded scan of this target".
4. Change something on the VM (stop one service), then scan again. The log shows "Compared with scan #N: x new, y fixed, z persisting" and a report path.
5. Open `reports\delta_scan*_to_scan*.md` and point at the evidence hashes and the "Evidence changed" column.
6. Show de-duplication in the database:
```
python -c "import sqlite3; c=sqlite3.connect('database/vuln_assessment.db'); [print(r) for r in c.execute('SELECT cve_id, times_seen, status FROM finding_registry ORDER BY times_seen DESC')]"
```
7. Show the results screen: "Risk score: X (asset criticality N)" in the details panel. Change a host's criticality in `config/asset_criticality.json`, rescan or reopen, and show the level change.

If the VM's IP changes (it is DHCP), add the new IP to `config/asset_criticality.json`, otherwise it uses the default criticality 3.

---

## 7. Gherkin scenarios (save as `features/risk_prioritisation.feature` and `features/delta_report.feature`)

These are feature files only. The step definitions still have to be written with whichever BDD tool you use (behave or pytest-bdd). Tell me which one and I will write them.

```gherkin
Feature: Reproducible risk prioritisation
  Scenario: Same findings in any order give the same ranking
    Given a scan with 6 findings on two hosts
    When the findings are ranked 25 times with the rows shuffled each time
    Then every ranking is identical

  Scenario: Asset criticality changes the risk score
    Given a finding with CVSS 7.5 on a host with asset criticality 5
    When the finding is scored
    Then the risk score is 9.0 and the band is CRITICAL

  Scenario: The same CVE on a rescan is recorded once
    Given CVE-2011-2523 was found on 192.168.56.102 port 21 in scan 1
    When scan 2 finds the same CVE on the same host and port
    Then the registry has one row for it with times_seen 2

  Scenario: A fallback CVSS score is labelled
    Given a finding whose only NVD score is CVSS v2.0
    When the finding is prioritised
    Then its score basis is "CVSS v2.0 (fallback)"

Feature: Delta reporting
  Scenario: A rescan reports new, fixed and persisting findings
    Given scan 1 found CVE-A and CVE-B on a host
    And scan 2 of the same host found CVE-B and CVE-C
    When the delta report is produced
    Then CVE-C is new, CVE-A is fixed and CVE-B is persisting
    And every entry has a 64-character evidence hash

  Scenario: A host that was not rescanned is never reported as fixed
    Given scan 1 covered hosts H1 and H2 and scan 2 covered only H1
    When the delta report is produced
    Then no finding on H2 is reported as fixed
    And H2 is listed as not rescanned

  Scenario: A scan with failed CVE lookups is not compared
    Given the NVD lookup failed for one service during a rescan
    When the scan finishes
    Then the scan is not recorded for comparison and the log explains why
```

---

## 8. Questions the examiner may ask, with answers you can adapt

**Scoring**

1. **How is a finding scored?** Risk score = CVSS base score x asset-criticality multiplier (0.8, 0.9, 1.0, 1.1, 1.2 for levels 1 to 5), capped at 10. The band uses the thresholds 9, 7 and 4 that the project already used.

2. **Why a multiplier and not CVSS environmental metrics?** CVSS v3.1 does define environmental metrics, but they need per-asset confidentiality, integrity and availability requirements and modified base metrics. An SME IT officer can answer one question, "how important is this machine, 1 to 5?" So I used a simple, explainable multiplier. The weights are my judgement, not a standard. That is a limitation, and calibrating them with the stakeholders is a next step.

3. **Why cap at 10?** To stay on the 0 to 10 scale and keep the same band thresholds. Sorting uses the uncapped score, so findings that tie at 10 still keep a clear order.

4. **How do you prove the ranking is reproducible?** There is no randomness and no timestamps in the score. The sort has a complete tie-break chain: score, CVSS, numeric IP, port, protocol, CVE ID. A test shuffles the input with 25 different seeds and asserts an identical result, and another test repeats the run.

5. **Why sort IPs numerically?** As text, `192.168.56.100` sorts before `192.168.56.20`. A test covers this.

6. **What if NVD only has a CVSS v2 score?** The matcher prefers v3.1, then v3.0, v4.0, then v2. Anything other than 3.1 is labelled "fallback" in the finding and shown in the delta report. This is a known limitation of the challenge wording "CVSS v3.1".

7. **Why is a 9.8 on a low-criticality asset only HIGH?** That is the point of criticality-weighted prioritisation: limited fixing time goes to the assets that matter most. It is documented in the decision table. The raw CVSS is still shown beside the risk score.

**De-duplication and delta**

8. **What makes two findings "the same"?** The fingerprint: SHA-256 of host, port, protocol and CVE ID. The same CVE on a different port or host is a different finding, because the exposure is different.

9. **Where is de-duplication enforced?** In the database: `UNIQUE(scan_id, fingerprint)` on the per-scan table, and one `finding_registry` row per fingerprint. Rescans update `last_seen` and `times_seen` instead of inserting a copy. Saving the same scan twice changes nothing.

10. **What is in the evidence hash, and why no timestamp?** SHA-256 over canonical JSON of host, port, protocol, service, version, banner, CVE ID, CVSS and CVSS version. With no timestamp, an unchanged finding keeps the same hash on every scan, and a change in the service version or the score changes the hash. The report marks that as "evidence changed".

11. **Does the hash prove the report was not tampered with?** No. It identifies the evidence, so you can detect that it changed between scans, but anyone who edits both the data and the hash would not be caught. Real tamper-evidence needs signing or hash chaining. I would list this as a limitation and future work.

12. **How do you avoid false "fixed" findings?** Two rules. A finding is only fixed if its host was scanned again, and hosts not rescanned are listed separately. And if any NVD lookup failed during a scan, that scan is not recorded for comparison, because a missing answer would look like a fixed vulnerability.

13. **What does a rescan with no open ports do?** The existing GUI flow stops at "No open ports found" and records nothing. A host that went down is therefore not reported as "everything fixed".

**Process and engineering**

14. **How did you protect the as-built behaviour when you changed `risk_scorer.py`?** I wrote 20 characterisation tests against the unchanged code first and committed them. After the change they still pass, because with the default criticality (3, multiplier 1.0) the output is identical.

15. **How did you check the new-code quality gates?** pytest-cov gives 97% line and branch coverage on the new modules, and Lizard reports no function over CC 10 or 40 lines. Two functions were over the length limit at first, so I split them.

16. **How would you add a new severity rule live (the defense gate)?** First write a Gherkin scenario for the rule and watch it fail. Then change one place, `score_finding` or `severity_band` in `analysis/prioritiser.py`, and re-run the tests. Practise this once with a rule such as "findings on a criticality-5 host are never below MEDIUM". Make sure you can explain every line in that file, because you will be asked.

**Honest limitations to volunteer**
- Multiplier weights are a judgement call and need stakeholder calibration.
- Findings with no matching CVE are not part of the delta, so a newly opened port with no CVE does not appear.
- Delta works per single target; whole-network scans need the host list passed through (the adapter supports a per-entry host already).
- The PDF report does not yet include the delta section.

---

## 9. Risks and what is still open (use for the risk register and RMMM)

| ID | Risk | Mitigation |
|---|---|---|
| R-1 | NVD timeout makes a rescan report false "fixed" | Failed-lookup counter; scan not recorded. Next: show "unknown" in the delta instead of skipping. |
| R-2 | Criticality config keyed by IP; a DHCP change silently gives default 3 | Document it; consider a log line when the target is not in the config. |
| R-3 | Property 2 (throttling) not started, with 254 hosts x 1,000 ports needing host discovery first to fit 15 min at 200 pps | Do host discovery, scan only live hosts, measure with a pcap. |
| R-4 | Property 1 evidence missing (pcap showing zero packets for 20 refusals, plus an automated test) | Quick win: tshark capture + pytest of the 20 attempts. |
| R-5 | Commit-day distribution (8 days, no day over 25%) | Spread remaining work over several days; never rewrite dates or history. |

Still to do for the challenge: property 1 evidence, property 2 end to end, BDD step definitions, a delta section in the PDF, and the one-command runner for VS1, VS2 and VS3.

---

## 10. AI disclosure text for `docs/ai-disclosure.md` (edit it so it is true for you)

> On 24 November 2026 I used Claude (Anthropic) as a coding assistant for Signature Challenge properties 3 and 4. Claude drafted `analysis/prioritiser.py`, `analysis/delta.py`, `analysis/scan_integration.py`, `database/findings_store.py`, `delta_tool.py` and their tests, and proposed small edits to `risk_scorer.py`, `vuln_matcher.py`, `scan_view.py` and `results_view.py`. I gave it my existing `db.py`, `risk_scorer.py`, `vuln_matcher.py`, `scan_view.py` and `results_view.py` as context. I ran all tests on my own machine, read the code, and committed it in separate commits. The formula, the multipliers and the design of the finding fingerprint and evidence hash were discussed with Claude; [state here which parts you chose yourself and which you changed]. I can explain every file in the defense.

Add the prompts you used (screenshots or exported chat) next to this file, because the card asks for prompts and what you kept.
