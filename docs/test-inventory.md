# NVAS test inventory: properties 3 and 4
Charles Chima, 24311351002, token CC02-P95R-SZ26. 24 Nov 2026

**113 tests in 6 files.** Run them all with `python -m pytest -q`; one file with `python -m pytest tests/test_delta.py -q`.
These are the tests delivered with the risk-prioritisation and delta-reporting work. Your existing tests (`test_auth.py`, `test_port_scanner.py`, `test_report_generator.py`, and anything else in `tests/`) are separate and add to the total.

| File | Tests | Kind | Property |
|---|---|---|---|
| `test_characterise_risk_scorer.py` | 20 | Characterisation of as-built code | 3 |
| `test_prioritiser.py` | 43 | Unit | 3 (and the hashes used by 4) |
| `test_delta.py` | 19 | Unit and database integration | 4 |
| `test_scan_integration.py` | 16 | Integration (matcher output to saved findings and delta) | 3 and 4 |
| `test_rank_findings_criticality.py` | 12 | Unit (criticality in the GUI ranking, NVD parser) | 3 |
| `test_matcher_failures.py` | 3 | Unit with mocked network | 4 (fault tolerance) |

---

## 1. `test_characterise_risk_scorer.py` (20): records what the AS-BUILT `risk_scorer.py` does
Written and run against the unchanged code before it was modified. They prove the criticality change did not alter existing behaviour.

| Test | What it checks |
|---|---|
| `test_score_to_level_boundaries` (9 cases) | CVSS to band at the boundaries the assignment names: None -> INFO, 0.0 -> LOW, 3.9 -> LOW, 4.0 -> MEDIUM, 6.9 -> MEDIUM, 7.0 -> HIGH, 8.9 -> HIGH, 9.0 -> CRITICAL, 10.0 -> CRITICAL |
| `test_risk_order_is_most_severe_first` | `RISK_ORDER` is CRITICAL, HIGH, MEDIUM, LOW, INFO |
| `test_info_is_labelled_no_match` | INFO shows as "NO MATCH" (not "safe"); other levels keep their name |
| `test_rows_ordered_by_top_cvss_descending` | Services are ranked 1, 2, 3 by their highest CVSS |
| `test_tie_broken_by_more_cves_then_lower_port` | Equal top scores: more CVEs first, then lower port number |
| `test_services_without_cves_come_last_and_unranked` | A service with no CVEs sorts last, has rank None and level INFO |
| `test_cves_inside_a_row_sorted_by_score_then_id` | CVEs in one row go by score, then CVE ID |
| `test_row_level_follows_top_score` | A 9.8 top score gives CRITICAL; a 3.0 gives LOW |
| `test_all_scores_none_gives_info_but_still_ranked` | CVEs with no score give INFO but the service still gets a rank |
| `test_product_falls_back_to_service_then_unknown` | Name shown is product, else service, else "unknown" |
| `test_match_type_is_passed_through` | The match type (e.g. "Name only") reaches the row |
| `test_same_input_gives_same_output` | Reversed input gives an identical result |

---

## 2. `test_prioritiser.py` (43): scoring, ranking, de-duplication, hashes

**Scoring formula**

| Test | What it checks |
|---|---|
| `test_default_criticality_keeps_cvss` | Criticality 3 leaves the score unchanged (7.5 stays 7.5) |
| `test_higher_criticality_raises_score` | Criticality 5 scores higher than 3 |
| `test_lower_criticality_lowers_score` | Criticality 1 scores lower than 3 |
| `test_risk_score_is_capped_at_ten` | 9.8 x 1.2 = 11.76 raw, but the risk score is 10.0 |
| `test_severity_bands` (9 cases) | Score to band: 10 and 9 CRITICAL, 8.9 and 7.0 HIGH, 6.9 and 4.0 MEDIUM, 3.9 and 0.1 LOW, 0.0 INFO |
| `test_invalid_criticality_rejected` (5 cases) | Criticality 0, 6, -1, "x" and None raise an error |
| `test_cvss_out_of_range_rejected` | A CVSS of 11 raises an error |

**Reproducible ranking**

| Test | What it checks |
|---|---|
| `test_ranking_is_same_for_any_input_order` | 25 random shuffles of the input all give the identical ranking |
| `test_ranking_is_same_across_repeated_runs` | Running twice gives identical output |
| `test_ranks_are_consecutive_from_one` | Ranks are 1, 2, 3 ... with no gaps |
| `test_asset_criticality_changes_order` | A 6.0 on a criticality-5 host (7.2) outranks a 7.0 on a default host |
| `test_tie_break_is_deterministic_by_host_then_port` | Equal scores order by host, then port |
| `test_numeric_ip_order_not_string_order` | `192.168.56.20` sorts before `192.168.56.100` |

**De-duplication**

| Test | What it checks |
|---|---|
| `test_duplicate_cve_same_host_port_collapses` | The same CVE on the same host and port becomes one finding |
| `test_same_cve_on_different_ports_is_not_duplicate` | Different port means a different finding |
| `test_same_cve_on_different_hosts_is_not_duplicate` | Different host means a different finding |
| `test_duplicate_keeps_higher_cvss` | When duplicates differ, the higher CVSS is kept |
| `test_cve_case_and_whitespace_normalised` | `cve-2011-2523` and ` CVE-2011-2523 ` count as the same CVE |
| `test_rows_without_cve_are_skipped` | Rows with no CVE produce no finding |

**Fingerprint and evidence hash**

| Test | What it checks |
|---|---|
| `test_fingerprint_is_stable` | Same host, port, protocol, CVE (any case) gives the same fingerprint |
| `test_fingerprint_differs_per_port` | Different port gives a different fingerprint |
| `test_evidence_hash_is_64_hex` | The hash is a 64-character hex SHA-256 |
| `test_evidence_hash_stable_for_same_evidence` | Same evidence gives the same hash every time |
| `test_evidence_hash_changes_when_version_changes` | A different service version changes the hash but not the fingerprint |
| `test_evidence_hash_changes_when_cvss_changes` | A different CVSS score changes the hash |

**Input handling**

| Test | What it checks |
|---|---|
| `test_alternative_key_names_accepted` | `ip`, `portid`, `cve`, `cvss_score` keys are understood |
| `test_v2_score_is_flagged_as_fallback` | CVSS version 2.0 is labelled as a fallback |
| `test_v31_basis_is_default` | With no version given, the basis is "CVSS v3.1" |
| `test_missing_host_rejected` | A row with no host raises an error |
| `test_load_criticality_missing_file_gives_default` | No config file means default criticality 3 |
| `test_load_criticality_reads_and_validates` | The JSON config is read, and an invalid level (9) raises an error |

---

## 3. `test_delta.py` (19): delta report and finding registry (uses a real in-memory SQLite database)

**Classification**

| Test | What it checks |
|---|---|
| `test_new_fixed_persisting_classified` | A in scan 1 only is fixed, C in scan 2 only is new, B in both is persisting |
| `test_identical_rescan_has_only_persisting` | Same findings twice gives 0 new, 0 fixed |
| `test_everything_fixed_when_host_clean_on_rescan` | A rescanned host with no findings means all its old findings are fixed |
| `test_host_not_rescanned_is_not_reported_fixed` | A host missing from scan 2 is listed as not rescanned, not as fixed |
| `test_new_host_findings_count_as_new` | Findings on a newly scanned host are new, and the host is listed as added |
| `test_same_cve_other_port_is_a_different_finding` | Same CVE on a different port shows as one new and one fixed |

**Evidence hashes**

| Test | What it checks |
|---|---|
| `test_every_entry_has_64_char_evidence_hash` | New, fixed and persisting entries all carry a 64-character hash |
| `test_unchanged_persisting_keeps_same_hash` | An unchanged finding has the same hash in both scans |
| `test_changed_evidence_is_flagged` | A changed service version sets "evidence changed" and changes the hash |
| `test_delta_is_reproducible` | The same two scans give the same delta (ignoring the generated-at time) |

**De-duplication on rescans**

| Test | What it checks |
|---|---|
| `test_rescan_does_not_create_duplicate_registry_rows` | Three scans of the same finding give one row with `times_seen` 3 |
| `test_saving_same_scan_twice_is_idempotent` | Saving a scan twice does not double count |
| `test_fixed_finding_leaves_open_list` | A fixed finding drops out of the open list |
| `test_reappearing_finding_reopens` | A fixed finding that returns reopens, keeping its first-seen scan |
| `test_unscanned_host_stays_open_in_registry` | A host not covered by a scan keeps its findings open |

**Errors and output**

| Test | What it checks |
|---|---|
| `test_delta_for_unknown_scan_raises` | Asking for a scan that was never saved raises an error |
| `test_compute_delta_works_without_database` | The comparison works on plain dictionaries |
| `test_markdown_contains_sections_and_hash_prefix` | The Markdown report has all three sections and the hash prefix |
| `test_write_report_creates_json_and_markdown` | Both report files are written and the JSON is valid |

---

## 4. `test_scan_integration.py` (16): from matcher output to saved findings and delta

| Test | What it checks |
|---|---|
| `test_flatten_gives_one_row_per_cve` | One matcher service with 2 CVEs becomes 2 rows carrying the target |
| `test_service_without_cves_gives_no_rows` | A service with no CVEs produces no rows |
| `test_missing_score_becomes_zero` | A CVE with no score becomes CVSS 0.0 |
| `test_product_preferred_over_service_name` | The product name is used as the service name |
| `test_entry_host_overrides_target` | A host on the entry beats the scan target |
| `test_first_scan_has_no_delta` | First scan: no previous run, delta is None, ranked from 1 |
| `test_second_scan_produces_delta` | Second scan correctly lists new, fixed and persisting CVEs |
| `test_identical_rescan_is_all_persisting_and_deduplicated` | Identical rescan: all persisting, registry rows seen twice |
| `test_different_targets_are_not_compared` | A scan of another target is not compared with this one |
| `test_duplicate_cve_in_matcher_output_collapses` | The same CVE listed twice becomes one finding |
| `test_scan_with_no_cves_still_records_run_and_marks_fixed` | A scan with no CVEs is recorded, and old findings become fixed |
| `test_last_two_runs` | The two most recent runs of a target are found, and other targets are ignored |
| `test_reports_written_when_enabled` | A report file appears on the second scan |
| `test_matcher_cvss_version_reaches_findings` | v2.0 is labelled fallback, v3.1 is not |
| `test_version_change_between_scans_marks_evidence_changed` | A score moving from v2 to v3.1 changes the evidence hash |
| `test_report_paths_returned_on_second_scan` | No paths on scan 1; both files exist after scan 2 |

---

## 5. `test_rank_findings_criticality.py` (12): the GUI ranking and the NVD parser

| Test | What it checks |
|---|---|
| `test_no_target_means_plain_cvss_behaviour` | With no target, risk score equals CVSS and criticality is 3 |
| `test_high_criticality_raises_level` | 7.5 on a criticality-5 host becomes 9.0, CRITICAL |
| `test_low_criticality_lowers_level` | 9.8 on a criticality-1 host becomes 7.84, HIGH |
| `test_unlisted_host_uses_default_criticality` | A host not in the config uses criticality 3 |
| `test_top_cvss_stays_the_raw_score` | `top_cvss` still shows the raw score (5.0) beside the risk score (6.0) |
| `test_risk_score_capped_at_ten` | The score never goes above 10 |
| `test_ranking_still_deterministic_with_criticality` | Reversed input gives the same order with criticality applied |
| `test_missing_config_file_falls_back_to_default` | A missing config file means criticality 3, with no crash |
| `test_parse_reports_v31` | The NVD parser records version "3.1" |
| `test_parse_prefers_v31_over_v2` | When both exist, the 3.1 score is used |
| `test_parse_flags_v2_fallback` | With only v2, the version is "2.0" and the severity is kept |
| `test_parse_without_metrics_has_no_version` | No metrics gives no score and no version |

---

## 6. `test_matcher_failures.py` (3): a failed NVD lookup must never look like "no CVEs"

| Test | What it checks |
|---|---|
| `test_failed_request_is_counted` | A network error after all retries increments the failure counter |
| `test_unknown_cpe_404_is_not_a_failure` | A 404 for an unknown CPE is a normal "nothing found", not a failure |
| `test_counter_resets_at_the_start_of_each_scan` | The counter is reset to 0 when a new scan starts |

---

## What these tests do NOT cover
- The Tkinter screens (`scan_view.py`, `results_view.py`) and the `delta_tool.py` command line. Those were checked by syntax and by testing the logic they call, so try them by hand.
- The PDF report (there is no delta section in it yet).
- Property 1 (scope enforcement with packet capture) and property 2 (throttling). There are no tests for these in this set.

## One quirk the tests record
The as-built `score_to_level(0.0)` returns LOW, while the new `severity_band(0.0)` returns INFO. A CVSS of exactly 0.0 is very rare, but it is a real inconsistency between the old and new code. You could log it in your defect log and decide which behaviour is right.
