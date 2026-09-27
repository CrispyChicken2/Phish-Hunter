"""How the alert threshold trades precision against recall.

The configured 0.7 was chosen by eye on a single sample. This recomputes the
outcome at every threshold from scores already in hand: no re-scoring, no model
calls, so the whole curve costs one pass over the dataset.

It also reports how many sites each threshold would alert on, because a threshold
is an operational decision as much as a statistical one: a value with better recall
that triples the queue may still be the wrong choice.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from lookalike_hunter.classify.schema import Label

# Fine enough to show where the curve turns, coarse enough to read as a table.
DEFAULT_THRESHOLDS: tuple[float, ...] = (0.4, 0.5, 0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95, 1.0)


@dataclass(frozen=True, slots=True)
class SweepPoint:
    threshold: float
    alerts: int  # how many sites would be flagged, i.e. the analyst's queue
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    is_configured: bool = False


@dataclass(frozen=True, slots=True)
class ThresholdSweep:
    points: list[SweepPoint] = field(default_factory=list)
    configured: float = 0.0

    @property
    def best_f1(self) -> SweepPoint | None:
        return max(self.points, key=lambda p: p.f1) if self.points else None


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def sweep_thresholds(
    scored: Sequence[tuple[str, float]],
    configured: float,
    thresholds: Sequence[float] = DEFAULT_THRESHOLDS,
) -> ThresholdSweep:
    """Precision and recall at each threshold, from (expected label, score) pairs.

    Only the phishing class is swept: the threshold decides what gets alerted on,
    and everything below it is treated as not worth an analyst's time.
    """
    phishing = str(Label.PHISHING)
    points: list[SweepPoint] = []
    for threshold in sorted(thresholds):
        alerts = [expected for expected, score in scored if score >= threshold]
        true_positives = sum(1 for expected in alerts if expected == phishing)
        false_positives = len(alerts) - true_positives
        false_negatives = sum(
            1 for expected, score in scored if expected == phishing and score < threshold
        )
        precision = _ratio(true_positives, len(alerts))
        recall = _ratio(true_positives, true_positives + false_negatives)
        denominator = precision + recall
        points.append(
            SweepPoint(
                threshold=threshold,
                alerts=len(alerts),
                true_positives=true_positives,
                false_positives=false_positives,
                false_negatives=false_negatives,
                precision=precision,
                recall=recall,
                f1=round(2 * precision * recall / denominator, 4) if denominator else 0.0,
                is_configured=abs(threshold - configured) < 1e-9,
            )
        )
    return ThresholdSweep(points=points, configured=configured)
