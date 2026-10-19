"""Bootstrap intervals and the exact McNemar test: known values and determinism."""

from __future__ import annotations

import pytest

from lookalike_hunter.eval.stats import (
    bootstrap_intervals,
    discordant_counts,
    mcnemar_exact,
)


def test_mcnemar_no_disagreement_is_no_evidence() -> None:
    assert mcnemar_exact(0, 0) == 1.0


def test_mcnemar_readme_example_is_not_significant() -> None:
    # The README's 8b vs 14b case: 4 sites favour one model, 2 favour the other.
    # Two-sided exact p = 2 * (1 + 6 + 15) / 64 = 0.6875.
    assert mcnemar_exact(4, 2) == pytest.approx(0.6875)


def test_mcnemar_all_one_way_is_the_smallest_exact_value() -> None:
    # Five disagreements, all in one direction: 2 * (1 / 32).
    assert mcnemar_exact(5, 0) == pytest.approx(0.0625)


def test_mcnemar_is_symmetric_and_capped_at_one() -> None:
    assert mcnemar_exact(4, 2) == mcnemar_exact(2, 4)
    assert mcnemar_exact(10, 10) == 1.0


def test_discordant_counts_only_compares_shared_sites() -> None:
    first = {"a.example": True, "b.example": True, "c.example": False, "only-first": True}
    second = {"a.example": False, "b.example": True, "c.example": True, "only-second": True}
    only_first, only_second, shared = discordant_counts(first, second)
    assert (only_first, only_second, shared) == (1, 1, 3)


def test_bootstrap_is_deterministic_for_a_seed() -> None:
    pairs = (
        [("phishing", "phishing")] * 6 + [("phishing", "benign")] * 2 + [("benign", "benign")] * 4
    )
    first = bootstrap_intervals(pairs, resamples=200, seed=7)
    second = bootstrap_intervals(pairs, resamples=200, seed=7)
    assert first == second


def test_bootstrap_interval_brackets_the_observed_accuracy() -> None:
    pairs = (
        [("phishing", "phishing")] * 6 + [("phishing", "benign")] * 2 + [("benign", "benign")] * 4
    )
    intervals = bootstrap_intervals(pairs, resamples=500, seed=7)
    observed = 10 / 12
    assert intervals["accuracy"].low <= observed <= intervals["accuracy"].high
    assert 0.0 <= intervals["accuracy"].low <= intervals["accuracy"].high <= 1.0


def test_bootstrap_of_a_perfect_run_has_no_width() -> None:
    pairs = [("phishing", "phishing")] * 5 + [("benign", "benign")] * 5
    intervals = bootstrap_intervals(pairs, resamples=100, seed=1)
    assert intervals["accuracy"].low == intervals["accuracy"].high == 1.0


def test_bootstrap_of_nothing_is_zero() -> None:
    intervals = bootstrap_intervals([], resamples=10, seed=1)
    assert intervals["accuracy"].low == intervals["accuracy"].high == 0.0
