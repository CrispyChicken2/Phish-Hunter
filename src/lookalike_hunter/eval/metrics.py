"""Classification metrics, computed from an explicit confusion matrix.

Everything here is derived from counts a reader can recompute by hand from the
report. That is deliberate: a benchmark nobody can check is worth little.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class ClassMetrics:
    label: str
    support: int  # how many sites truly have this label
    predicted: int  # how many sites were given this label
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float


@dataclass(frozen=True, slots=True)
class Metrics:
    per_class: dict[str, ClassMetrics] = field(default_factory=dict)
    # confusion[expected][predicted] = count
    confusion: dict[str, dict[str, int]] = field(default_factory=dict)
    total: int = 0
    correct: int = 0
    accuracy: float = 0.0
    macro_precision: float = 0.0
    macro_recall: float = 0.0
    macro_f1: float = 0.0


def _ratio(numerator: int, denominator: int) -> float:
    """Zero rather than an error when a class was never predicted or never occurs."""
    return round(numerator / denominator, 4) if denominator else 0.0


def compute_metrics(pairs: Sequence[tuple[str, str]]) -> Metrics:
    """Build metrics from (expected, predicted) label pairs."""
    if not pairs:
        return Metrics()

    labels = sorted({label for pair in pairs for label in pair})
    confusion = {expected: dict.fromkeys(labels, 0) for expected in labels}
    for expected, predicted in pairs:
        confusion[expected][predicted] += 1

    support = Counter(expected for expected, _ in pairs)
    predicted_counts = Counter(predicted for _, predicted in pairs)

    per_class: dict[str, ClassMetrics] = {}
    for label in labels:
        true_positives = confusion[label][label]
        false_positives = predicted_counts[label] - true_positives
        false_negatives = support[label] - true_positives
        precision = _ratio(true_positives, predicted_counts[label])
        recall = _ratio(true_positives, support[label])
        denominator = precision + recall
        f1 = round(2 * precision * recall / denominator, 4) if denominator else 0.0
        per_class[label] = ClassMetrics(
            label=label,
            support=support[label],
            predicted=predicted_counts[label],
            true_positives=true_positives,
            false_positives=false_positives,
            false_negatives=false_negatives,
            precision=precision,
            recall=recall,
            f1=f1,
        )

    correct = sum(confusion[label][label] for label in labels)
    count = len(per_class)
    return Metrics(
        per_class=per_class,
        confusion=confusion,
        total=len(pairs),
        correct=correct,
        accuracy=_ratio(correct, len(pairs)),
        macro_precision=round(sum(m.precision for m in per_class.values()) / count, 4),
        macro_recall=round(sum(m.recall for m in per_class.values()) / count, 4),
        macro_f1=round(sum(m.f1 for m in per_class.values()) / count, 4),
    )
