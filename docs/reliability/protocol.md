# NVAS reliability test protocol (8 test hours and Jelinski-Moranda)
Charles Chima, 24311351002, token CC02-P95R-SZ26

Save as `docs/reliability/protocol.md`. Files you need: `scripts/jelinski_moranda.py`, `tests/test_jelinski_moranda.py`, `docs/reliability/failures_template.csv` (copy to `failures.csv`) and `docs/reliability/sessions_template.csv` (copy to `sessions.csv`).

---

## 1. What the card asks for

"Reliability campaign: 8 test hours" and "Fit the Jelinski-Moranda model to 8 test hours."

A **reliability test** runs the system the way real users would, for a measured amount of time, and records every **failure** (the system does something wrong) with the time it happened. The **Jelinski-Moranda (JM) model** then uses the gaps between failures to estimate how many faults are left and how often the system will fail from now on.

The model's idea: the software starts with N faults. Each failure is followed by removing one fault, so failures should become less frequent and the gaps between them should grow. If your failures are spread out more and more, JM can estimate N, the faults remaining, the current failure rate and the mean time to the next failure.

## 2. The honesty rule (read this first)

- **Never invent failure times.** The card's evidence is your own data. Examiners can ask to see the log, the sessions and the commits that fixed each failure.
- **A bad result is still a result.** If you see no failures, or too few, or the gaps are not growing, the model cannot be fitted. The script says so, and you report that plainly (section 8).
- **Only count test hours that really happened.** Record start and end times for each session.

## 3. Definitions

**Test hour:** one hour of wall-clock time during which the system is running and being exercised according to the operational profile (section 4). Hours are counted once, even if several things happen at the same time.

**Failure (software):** the system behaves differently from what it should. Examples for NVAS:
- the app crashes, freezes, or shows an unhandled error;
- a scan finishes but results are missing, duplicated or in the wrong order;
- a wrong answer, such as a finding shown as "fixed" when it was not fixed;
- an out-of-scope target is accepted, or an in-scope target is refused wrongly;
- the PDF report is wrong or cannot be created;
- the delta report disagrees with the two scans it compares.

**Not a software failure (log it, but leave it out of the JM fit, with the reason):**
- the VM was switched off or the network was down;
- the NVD service was unreachable (the system should handle that; if it handled it correctly, it is not a failure);
- user error, such as typing the wrong IP address.

If the system handled an environmental problem **badly** (for example it crashed when the NVD timed out), that is a software failure.

## 4. Operational profile: what to do during test hours

This is a suggested mix based on how an IT officer would use the tool. Adjust it, write down what you used, and keep to it.

| Share of time | Activity |
|---|---|
| 40% | Normal scan of the test VM, then open the results and CVE details |
| 15% | Rescan after changing something on the VM, then check the delta report |
| 10% | Export the PDF report |
| 10% | Bad input: out-of-scope address, empty field, malformed address, two scans started quickly |
| 10% | Login and roles: wrong password, locked account, a viewer trying to scan |
| 10% | Fault injection: disconnect the network during the CVE lookup, switch the VM off, close the window mid-scan |
| 5% | Look at old results and the registry |

## 5. How to get 8 test hours in your time

You have limited working time, so be realistic.

**Option A (best): an unattended runner.** A script drives the full scan pipeline repeatedly against the test VM while you do other work, and writes every error with a timestamp. Hours count while it runs. Send me `scope_tool.py` and the lines of `gui_main.py` or the app class that create the scope guard (`self.app.guard`), and I will write the runner so it can start before you sleep. It must use a separate database file so it does not touch your demo data, and it must respect the NVD rate limit.

**Option B: attended sessions.** For example four sessions of two hours, following the profile above. This costs most of a working day, so only use it if the runner is not possible.

**Option C: do not run it.** Then state clearly that no reliability campaign was run and no reliability figure is claimed (`docs/known-gaps.md` already says this).

Do not mix a real campaign with made-up hours to fill the gap.

## 6. Logging

**Sessions** (`docs/reliability/sessions.csv`): one row per session, with start, end, hours and what was done. The sum of hours is your total test time (the card wants 8).

**Failures** (`docs/reliability/failures.csv`), one row per software failure:

| Column | Meaning |
|---|---|
| `failure_no` | 1, 2, 3 in order |
| `cumulative_test_hours` | Test hours elapsed when it happened, for example 2.35 |
| `description` | What went wrong, in one sentence |
| `classification` | `software` (goes into the fit) or `excluded: <reason>` |
| `fixed_in_commit` | The commit that fixed the fault, or `not fixed` |

Take a screenshot or a log excerpt for each failure and keep it. The same failures are your **defect log** (the card wants at least 5 real defects), so the two records should agree.

**Fix as you go.** The model assumes the fault is removed after each failure. Fix it, commit it, and carry on testing. If you cannot fix a fault, write `not fixed` and say that the model's assumption is only approximately met.

## 7. Running the analysis

```
python scripts/jelinski_moranda.py docs/reliability/failures.csv --total-hours 8
```

Only rows classified as software failures should be in `failures.csv`; keep excluded events in a separate sheet or in the description of `sessions.csv`.

The output gives:

| Result | Meaning |
|---|---|
| Estimated initial faults N | How many faults the model thinks the software started with |
| Faults remaining | N minus the failures observed |
| Failure rate | Expected failures per hour from now on |
| MTTF | Mean time to the next failure, in hours (1 / failure rate) |
| P(no failure in next t h) | Chance of getting through t hours without a failure |

The script needs **at least 5 failures** and **growing gaps** between them. If either is missing it explains why and stops.

**Synthetic example, to understand the output only (do not submit these numbers):** seven failures at 0.4, 1.1, 2.0, 3.2, 4.5, 6.0 and 7.6 test hours give N of about 9.0, about 2.0 faults remaining, a failure rate of about 0.35 per hour, an MTTF of about 2.9 hours, and a 71% chance of no failure in the next hour.

## 8. If the model cannot be fitted

- **No failures in 8 hours:** report the rule of three. With zero failures in T hours, the 95% upper bound on the failure rate is 3 / T, so 0.375 failures per hour for 8 hours. Say that the model could not be fitted because there were no failures, and that the system was not proven reliable, only that no failure was seen in this profile.
- **Fewer than 5 failures, or gaps not growing:** say that the JM model cannot be fitted to your data and why. You can still list the failures, their causes and fixes.
- **Never** change the data to make the fit work.

## 9. How to explain it in the presentation

> "I tested NVAS for [X] hours following an operational profile: [short summary]. I found [n] software failures, each logged with a time, a cause and the commit that fixed it. [If fitted:] The Jelinski-Moranda model estimates about [N] faults at the start and [r] remaining, a failure rate of [λ] per hour and a mean time to the next failure of [MTTF] hours. [If not fitted:] The model could not be fitted because [reason], so I report [rule-of-three bound / the list of failures]. The model assumes each fault is fixed after each failure and that all faults are equally likely to cause a failure, which is only approximately true, so I treat the result as an estimate."

**Questions to expect:** What is a failure in your system? Why did you exclude those events? What does the model assume? Why is the estimate unreliable with few failures? How many hours did you actually run, and where are the logs?

## 10. Checklist

- [ ] Operational profile written down (section 4)
- [ ] Sessions logged with real start and end times
- [ ] Every failure logged with time, description, class and fix
- [ ] Failures also appear in the defect log, with fix commits
- [ ] `python scripts/jelinski_moranda.py ...` output saved as `docs/reliability/jm-result.txt`
- [ ] Result, assumptions and limits written up honestly