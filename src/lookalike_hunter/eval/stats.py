"""Uncertainty for the evaluation: bootstrap intervals and a paired test.

Standard library only, so no new dependency. Both functions are deterministic: the
bootstrap takes a fixed seed, and the exact test has no randomness, so the same
dataset always gives the same report.
"""

from __future__ import annotations

import random
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from math import comb

from lookalike_hunter.eval.metrics import compute_metrics

# 10,000 resamples is the usual choice: the interval endpoints stop moving at the
# second decimal well before that. The seed is fixed so the report reproduces.
DEFAULT_RESAMPLES = 10_000
DEFAULT_SEED = 20261019
CONFIDENCE = 0.95


@dataclass(frozen=True, slots=True)
class Interval:
    low: float
    high: float


def bootstrap_intervals(
    pairs: Sequence[tuple[str, str]],
    *,
    resamples: int = DEFAULT_RESAMPLES,
    seed: int = DEFAULT_SEED,
) -> dict[str, Interval]:
    """95% percentile bootstrap intervals for accuracy and macro F1.

    Each resample draws as many sites as the dataset has, with replacement, and
    recomputes the metrics on that draw. The interval is the middle 95% of the
    resampled values. A class missing from a resample is left out of its macro
    average, which is why macro F1 is the less stable of the two figures.
    """
    if not pairs:
        return {"accuracy": Interval(0.0, 0.0), "macro_f1": Interval(0.0, 0.0)}

    rng = random.Random(seed)
    size = len(pairs)
    accuracies: list[float] = []
    macro_f1s: list[float] = []
    for _ in range(resamples):
        sample = [pairs[rng.randrange(size)] for _ in range(size)]
        metrics = compute_metrics(sample)
        accuracies.append(metrics.accuracy)
        macro_f1s.append(metrics.macro_f1)

    return {
        "accuracy": _percentile_interval(accuracies),
        "macro_f1": _percentile_interval(macro_f1s),
    }


def _percentile_interval(values: list[float]) -> Interval:
    values.sort()
    alpha = 1 - CONFIDENCE
    low_index = int(len(values) * alpha / 2)
    high_index = min(len(values) - 1, int(len(values) * (1 - alpha / 2)))
    return Interval(values[low_index], values[high_index])


def mcnemar_exact(only_first_right: int, only_second_right: int) -> float:
    """Two-sided exact McNemar test on the sites where two models disagree.

    Under the null hypothesis the two models are equally accurate, so each
    disagreement is equally likely to favour either one: a fair coin. The p-value is
    the chance of a split at least as lopsided, counted exactly with binomial
    coefficients. The chi-square approximation is avoided on purpose: it is unreliable
    when the disagreements are few, which is the usual case here.
    """
    discordant = only_first_right + only_second_right
    if discordant == 0:
        return 1.0
    smaller = min(only_first_right, only_second_right)
    one_tail: float = sum(comb(discordant, k) for k in range(smaller + 1)) / 2**discordant
    return float(min(1.0, 2 * one_tail))


def discordant_counts(
    first: Mapping[str, bool], second: Mapping[str, bool]
) -> tuple[int, int, int]:
    """Count sites judged by both models where exactly one of them was right.

    Returns (only first right, only second right, sites judged by both). Sites
    judged by only one model are not compared.
    """
    shared = first.keys() & second.keys()
    only_first = sum(1 for site in shared if first[site] and not second[site])
    only_second = sum(1 for site in shared if second[site] and not first[site])
    return only_first, only_second, len(shared)
