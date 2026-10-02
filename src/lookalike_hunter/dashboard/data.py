"""Reading findings for the dashboard.

Kept out of the Streamlit page so it can be tested: a page is awkward to test,
a function returning rows is not.

Everything here is attacker-influenced text, including what the database says
about where a screenshot lives. The page renders text with ``st.text`` (no
Markdown, no HTML), so the helpers here only strip control characters, bound the
length and defang URLs; the escaping that matters is choosing that element.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from lookalike_hunter.alert.sinks import clean, defang
from lookalike_hunter.capture.models import stored_capture_file
from lookalike_hunter.ingest.store import connect_with_retry

__all__ = ["Finding", "defang", "label_counts", "load_findings", "plain"]


def plain(value: object, limit: int = 500) -> str:
    """Hostile text for a plain-text element: control characters out, length bounded."""
    return clean(value, limit)


@dataclass(frozen=True, slots=True)
class Finding:
    fqdn: str
    brand: str | None
    label: str
    confidence: float
    score: float
    evidence: str | None
    final_url: str | None
    screenshot_path: str | None
    model: str | None
    classified_at: datetime
    alerted_at: datetime | None

    def screenshot_file(self, captures_dir: Path) -> Path | None:
        """Absolute path to the screenshot, or None when the file is gone.

        Stored paths are relative to the capture directory, because captures are
        written inside a container and read from the host. One pointing outside
        that directory is refused, so a tampered row cannot make the dashboard
        read and display an arbitrary file.
        """
        resolved = stored_capture_file(self.screenshot_path, captures_dir)
        return resolved if resolved is not None and resolved.is_file() else None


def load_findings(
    db_path: Path,
    labels: tuple[str, ...] = (),
    min_confidence: float = 0.0,
    limit: int = 200,
    model: str | None = None,
) -> list[Finding]:
    """Latest verdict per hostname, newest first.

    Opened read-only through the retrying helper so the dashboard can be left open
    while ingestion is writing.
    """
    if not db_path.exists():
        return []
    with connect_with_retry(db_path, read_only=True) as con:
        rows = con.execute(
            """
            WITH latest AS (
                SELECT fqdn, max(verdict_id) AS verdict_id FROM verdicts
                WHERE label <> 'error' AND (? IS NULL OR model = ?)
                GROUP BY fqdn
            )
            SELECT v.fqdn, v.brand_impersonated, v.label, v.confidence,
                   coalesce((SELECT max(m.score) FROM matches m WHERE m.fqdn = v.fqdn), 0.0),
                   v.evidence, c.final_url, c.screenshot_path, v.model,
                   v.classified_at, v.alerted_at
            FROM verdicts v
            JOIN latest USING (verdict_id)
            JOIN captures c USING (capture_id)
            WHERE (array_length(?) = 0 OR v.label IN (SELECT unnest(?)))
              AND v.confidence >= ?
            ORDER BY v.classified_at DESC, v.verdict_id DESC
            LIMIT ?
            """,
            [model, model, list(labels), list(labels), min_confidence, limit],
        ).fetchall()
    return [Finding(*row) for row in rows]


def label_counts(db_path: Path) -> dict[str, int]:
    """How many hostnames sit in each class, for the summary row."""
    if not db_path.exists():
        return {}
    with connect_with_retry(db_path, read_only=True) as con:
        rows = con.execute(
            """
            WITH latest AS (
                SELECT fqdn, max(verdict_id) AS verdict_id FROM verdicts
                WHERE label <> 'error' GROUP BY fqdn
            )
            SELECT v.label, count(*) FROM verdicts v JOIN latest USING (verdict_id)
            GROUP BY v.label ORDER BY count(*) DESC
            """
        ).fetchall()
    return dict(rows)
