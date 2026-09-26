"""The evaluation result: what was measured, on what, and under which settings.

Written as JSON so a machine can diff two runs, and as Markdown so a human can read
one. Both carry the provenance (dataset, configuration, timestamp), because a metric
without its conditions cannot be compared with anything.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from lookalike_hunter.eval.metrics import Metrics

# The Scorer works on names alone, so it can never output "parked": a parking page
# and a phishing page have the same hostname shape. Stating this next to the numbers
# stops the baseline looking better than it is, and it is the gap the VLM must close.
SCORING_ONLY_CAVEAT = (
    "The scoring-only arm predicts phishing at or above the alert threshold and "
    "legitimate below it. It cannot predict parked or unreachable: those need the "
    "page, not the name. Parked sites therefore count against its precision."
)


@dataclass(frozen=True, slots=True)
class Prediction:
    fqdn: str
    expected: str
    predicted: str
    score: float
    brand: str | None = None
    note: str | None = None


@dataclass(frozen=True, slots=True)
class ArmResult:
    name: str
    metrics: Metrics
    predictions: list[Prediction] = field(default_factory=list)
    caveat: str | None = None

    @property
    def mistakes(self) -> list[Prediction]:
        return [p for p in self.predictions if p.expected != p.predicted]


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    dataset_path: str
    dataset_size: int
    generated_at: datetime
    alert_threshold: float
    arms: dict[str, ArmResult] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, default=str, sort_keys=True)

    def to_markdown(self) -> str:
        lines = [
            "# Evaluation report",
            "",
            f"- Dataset: `{self.dataset_path}` ({self.dataset_size} sites)",
            f"- Generated: {self.generated_at:%Y-%m-%d %H:%M:%S} UTC",
            f"- Alert threshold: {self.alert_threshold}",
            "",
        ]
        for arm in self.arms.values():
            lines += [f"## Arm: {arm.name}", ""]
            if arm.caveat:
                lines += [f"> {arm.caveat}", ""]
            m = arm.metrics
            lines += [
                f"Accuracy: **{m.accuracy:.2%}** ({m.correct}/{m.total}) · "
                f"macro F1: **{m.macro_f1:.4f}**",
                "",
                "| Class | Support | Predicted | TP | FP | FN | Precision | Recall | F1 |",
                "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
            ]
            for c in m.per_class.values():
                lines.append(
                    f"| {c.label} | {c.support} | {c.predicted} | {c.true_positives} | "
                    f"{c.false_positives} | {c.false_negatives} | {c.precision:.4f} | "
                    f"{c.recall:.4f} | {c.f1:.4f} |"
                )
            lines += ["", "### Confusion matrix (rows = expected, columns = predicted)", ""]
            labels = sorted(m.confusion)
            lines += [
                "| expected \\ predicted | " + " | ".join(labels) + " |",
                "|---" * (len(labels) + 1) + "|",
            ]
            for expected in labels:
                row = " | ".join(str(m.confusion[expected][p]) for p in labels)
                lines.append(f"| **{expected}** | {row} |")

            mistakes = arm.mistakes
            lines += ["", f"### Mistakes ({len(mistakes)})", ""]
            if mistakes:
                lines += [
                    "| Site | Expected | Predicted | Score |",
                    "|---|---|---|---:|",
                    *(
                        f"| `{p.fqdn}` | {p.expected} | {p.predicted} | {p.score:.2f} |"
                        for p in mistakes
                    ),
                ]
            else:
                lines.append("None.")
            lines.append("")
        return "\n".join(lines)


def write_report(report: EvaluationReport, out_dir: Path) -> tuple[Path, Path]:
    """Write both formats into a timestamped directory; returns their paths."""
    run_dir = out_dir / report.generated_at.strftime("%Y%m%dT%H%M%SZ")
    run_dir.mkdir(parents=True, exist_ok=True)
    json_path = run_dir / "report.json"
    markdown_path = run_dir / "report.md"
    json_path.write_text(report.to_json(), encoding="utf-8")
    markdown_path.write_text(report.to_markdown(), encoding="utf-8")
    return json_path, markdown_path
