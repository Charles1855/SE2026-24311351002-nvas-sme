"""
scripts/jelinski_moranda.py
Fit the Jelinski-Moranda software reliability model to a failure log.

Input: a CSV with at least the columns  failure_no, cumulative_test_hours
(see docs/reliability/failures_template.csv). Only SOFTWARE failures belong in it.

Model
-----
There are N faults at the start. Each failure is followed by removing one fault.
Before the i-th failure the failure rate is   lambda_i = phi * (N - (i - 1))
so the time x_i between failure i-1 and failure i is exponential with that rate.

Maximum likelihood (stops observing at the n-th failure):
    phi = n / sum_i (N - i + 1) * x_i
    N solves   sum_i 1 / (N - i + 1)  =  phi * sum_i x_i
A finite N exists only if the intervals tend to GROW (reliability growth):
    sum_i (i - 1) * x_i / sum_i x_i  >  (n - 1) / 2
If that fails, the data show no growth and the model cannot be fitted. Say so.

Run:  python scripts/jelinski_moranda.py docs/reliability/failures.csv --total-hours 8
"""
from __future__ import annotations

import argparse
import csv
import math
import sys
from dataclasses import dataclass

MIN_FAILURES = 5


class FitError(Exception):
    """The data do not allow a Jelinski-Moranda fit (and the reason says why)."""


@dataclass
class Fit:
    n: int                 # failures observed
    hours: float           # test hours up to the last failure
    n_hat: float           # estimated initial number of faults
    phi: float             # failure rate contributed by each remaining fault, per hour
    remaining: float       # estimated faults still in the software
    intensity: float       # current failure rate, failures per hour
    mttf: float            # mean time to next failure, hours

    def reliability(self, t: float) -> float:
        """Probability of no failure during the next t hours."""
        return math.exp(-self.intensity * t)


def read_failures(path: str) -> list[float]:
    """Cumulative failure times in hours, sorted, from the CSV."""
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if "cumulative_test_hours" not in (reader.fieldnames or []):
            # a missing column must never be read as "no failures"
            raise FitError("the CSV needs a 'cumulative_test_hours' column")
        rows = list(reader)
    try:
        return sorted(float(r["cumulative_test_hours"]) for r in rows if (r["cumulative_test_hours"] or "").strip())
    except ValueError as error:
        raise FitError(f"'cumulative_test_hours' must be numbers: {error}")


def intervals(times: list[float]) -> list[float]:
    """Inter-failure times x_1..x_n (the first is measured from time 0)."""
    previous, result = 0.0, []
    for t in times:
        if t < previous:
            raise FitError("failure times must not decrease")
        result.append(t - previous)
        previous = t
    return result


def has_growth(x: list[float]) -> bool:
    """True if the intervals tend to grow, so that a finite N exists."""
    n, total = len(x), sum(x)
    if total <= 0:
        return False
    return sum(i * xi for i, xi in enumerate(x)) / total > (n - 1) / 2


def _score(n_value: float, x: list[float]) -> float:
    """Derivative of the log-likelihood in N after substituting phi; zero at the MLE."""
    n = len(x)
    denominator = sum((n_value - i) * xi for i, xi in enumerate(x))
    left = sum(1.0 / (n_value - i) for i in range(n))
    return left - n * sum(x) / denominator


def fit(times: list[float]) -> Fit:
    n = len(times)
    if n < MIN_FAILURES:
        raise FitError(f"only {n} failures; at least {MIN_FAILURES} are needed to fit the model")
    x = intervals(times)
    if not has_growth(x):
        raise FitError("no evidence of reliability growth (the gaps between failures are not getting longer), "
                       "so the maximum-likelihood N is infinite and the model cannot be fitted")
    low = (n - 1) + 1e-9
    high = n + 1.0
    while _score(high, x) > 0:          # the score is positive near low and turns negative for large N
        high *= 2
        if high > 1e9:
            raise FitError("could not bracket N; the data are too close to no growth")
    for _ in range(200):
        mid = (low + high) / 2
        if _score(mid, x) > 0:
            low = mid
        else:
            high = mid
    n_hat = (low + high) / 2
    phi = n / sum((n_hat - i) * xi for i, xi in enumerate(x))
    remaining = n_hat - n
    intensity = phi * remaining
    mttf = math.inf if intensity <= 0 else 1.0 / intensity
    return Fit(n, times[-1], n_hat, phi, remaining, intensity, mttf)


def rule_of_three(total_hours: float) -> float:
    """95% upper bound on the failure rate when NO failures were seen in total_hours."""
    return 3.0 / total_hours


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Jelinski-Moranda reliability fit")
    parser.add_argument("csv", help="failure log CSV")
    parser.add_argument("--total-hours", type=float, default=None, help="total test hours of the campaign")
    args = parser.parse_args(argv)

    times = read_failures(args.csv)
    print(f"Failures in the log: {len(times)}" + (f"   Total test hours: {args.total_hours}" if args.total_hours else ""))
    if not times:
        if args.total_hours:
            print(f"No failures observed. 95% upper bound on the failure rate (rule of three): "
                  f"{rule_of_three(args.total_hours):.3f} per hour. The model cannot be fitted without failures.")
        else:
            print("No failures observed and no --total-hours given.")
        return 0
    try:
        result = fit(times)
    except FitError as error:
        print("Cannot fit Jelinski-Moranda:", error)
        return 1
    print(f"Estimated initial faults N      : {result.n_hat:.2f}")
    print(f"Per-fault failure rate phi      : {result.phi:.4f} per hour")
    print(f"Estimated faults remaining      : {result.remaining:.2f}")
    print(f"Current failure rate            : {result.intensity:.4f} per hour")
    print(f"Mean time to next failure (MTTF): {result.mttf:.2f} hours")
    for t in (1, 8):
        print(f"P(no failure in the next {t} h)   : {result.reliability(t):.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())