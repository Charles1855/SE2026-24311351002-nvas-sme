"""Tests for scripts/jelinski_moranda.py. The numbers here are synthetic: they check the maths only."""
import math
import random

import pytest

from scripts.jelinski_moranda import (
    FitError, MIN_FAILURES, fit, has_growth, intervals, read_failures, rule_of_three, _score, main,
)

# 8 failures whose gaps clearly grow (reliability growth)
GROWING = [0.3, 0.9, 1.8, 3.0, 4.6, 6.6, 9.0, 11.8]


def test_intervals_are_differences_from_zero():
    assert intervals([1.0, 3.0, 6.0]) == [1.0, 2.0, 3.0]


def test_decreasing_times_rejected():
    with pytest.raises(FitError):
        intervals([2.0, 1.0])


def test_growth_detected_for_growing_gaps():
    assert has_growth(intervals(GROWING))


def test_no_growth_for_equal_gaps():
    assert not has_growth(intervals([1, 2, 3, 4, 5, 6]))


def test_no_growth_for_shrinking_gaps():
    assert not has_growth(intervals([5, 9, 12, 14, 15, 15.5]))


def test_too_few_failures_rejected():
    with pytest.raises(FitError, match="at least"):
        fit([1.0, 2.0, 4.0])
    assert MIN_FAILURES == 5


def test_fit_refuses_data_without_growth():
    with pytest.raises(FitError, match="no evidence"):
        fit([1, 2, 3, 4, 5, 6])


def test_fit_satisfies_the_likelihood_equations():
    result = fit(GROWING)
    x = intervals(GROWING)
    assert result.n_hat > len(GROWING) - 1
    assert abs(_score(result.n_hat, x)) < 1e-6
    phi = len(x) / sum((result.n_hat - i) * xi for i, xi in enumerate(x))
    assert result.phi == pytest.approx(phi)


def test_derived_quantities_are_consistent():
    result = fit(GROWING)
    assert result.remaining == pytest.approx(result.n_hat - result.n)
    assert result.intensity == pytest.approx(result.phi * result.remaining)
    assert result.mttf == pytest.approx(1 / result.intensity)
    assert result.reliability(0) == 1.0
    assert 0 < result.reliability(8) < result.reliability(1) < 1


def test_fit_recovers_parameters_from_simulated_data():
    """Simulate a program with N=25 faults, phi=0.04, test until 20 failures, fit many times."""
    estimates = []
    for seed in range(200):
        rng = random.Random(seed)
        clock, times = 0.0, []
        for i in range(20):
            clock += rng.expovariate(0.04 * (25 - i))
            times.append(clock)
        try:
            estimates.append(fit(times).n_hat)
        except FitError:
            pass
    assert len(estimates) > 150                      # a finite estimate exists for most runs
    estimates.sort()
    median = estimates[len(estimates) // 2]
    assert 21 <= median <= 32                        # close to the true 25


def test_rule_of_three():
    assert rule_of_three(8) == pytest.approx(0.375)


def test_read_failures_sorts_and_ignores_blanks(tmp_path):
    path = tmp_path / "f.csv"
    path.write_text("failure_no,cumulative_test_hours,description\n2,3.5,b\n1,1.0,a\n3,,blank\n", encoding="utf-8")
    assert read_failures(str(path)) == [1.0, 3.5]


def test_read_failures_needs_the_hours_column(tmp_path):
    path = tmp_path / "f.csv"
    path.write_text("failure_no,hours\n1,2\n", encoding="utf-8")
    with pytest.raises(FitError):
        read_failures(str(path))


def test_main_prints_a_fit(tmp_path, capsys):
    path = tmp_path / "f.csv"
    path.write_text("failure_no,cumulative_test_hours\n" + "\n".join(f"{i+1},{t}" for i, t in enumerate(GROWING)), encoding="utf-8")
    assert main([str(path), "--total-hours", "12"]) == 0
    out = capsys.readouterr().out
    assert "Estimated initial faults" in out and "Mean time to next failure" in out


def test_main_reports_no_failures_with_rule_of_three(tmp_path, capsys):
    path = tmp_path / "f.csv"
    path.write_text("failure_no,cumulative_test_hours\n", encoding="utf-8")
    assert main([str(path), "--total-hours", "8"]) == 0
    assert "0.375" in capsys.readouterr().out


def test_main_returns_error_code_when_not_fittable(tmp_path, capsys):
    path = tmp_path / "f.csv"
    path.write_text("failure_no,cumulative_test_hours\n" + "\n".join(f"{i},{i}" for i in range(1, 8)), encoding="utf-8")
    assert main([str(path)]) == 1
    assert "Cannot fit" in capsys.readouterr().out


def test_non_numeric_hours_rejected(tmp_path):
    path = tmp_path / "f.csv"
    path.write_text("failure_no,cumulative_test_hours\n1,abc\n", encoding="utf-8")
    with pytest.raises(FitError, match="numbers"):
        read_failures(str(path))


def test_main_on_missing_column_is_not_reported_as_zero_failures(tmp_path, capsys):
    path = tmp_path / "f.csv"
    path.write_text("failure_no,hours\n1,2\n", encoding="utf-8")
    with pytest.raises(FitError):
        main([str(path), "--total-hours", "8"])