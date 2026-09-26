"""Assemble candidate sites for a human to label.

Kept apart from evaluation on purpose: this touches the network and its results
change hourly, while a measurement must be reproducible.

Nothing here assigns ground truth. Every candidate is written with `expected: null`
and a *suggestion* recording where it came from; a human decides the label by
looking at the capture. The loader refuses an unlabelled file, so an unreviewed
dataset cannot quietly become a benchmark.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path

from lookalike_hunter.config import BrandConfig
from lookalike_hunter.eval.dataset import iter_dataset
from lookalike_hunter.eval.feeds import FeedEntry, filter_to_brands, parse_url_feed
from lookalike_hunter.ingest.store import connect_with_retry
from lookalike_hunter.logging import get_logger

log = get_logger(__name__)

# Domains the Scorer flagged during calibration that a human judged not to be
# attacks. A benchmark made only of clear-cut cases would say nothing useful, so
# the hard negatives are seeded in deliberately. They are still candidates: the
# reviewer confirms or overrides each one.
KNOWN_HARD_NEGATIVES: tuple[tuple[str, str], ...] = (
    ("hummelcloud.net", "word ending in l before cloud, read as icloud"),
    ("bigbullcloud.com", "same pattern"),
    ("vercelcloud.com", "same pattern"),
    ("vesselcloud.dev", "same pattern"),
    ("voxelclouddao.xyz", "same pattern"),
    ("ateliergamelle.com", "rn/m folding brushed against ameli"),
    ("thedarnells.org", "same pattern"),
    ("amell.family", "surname colliding with a short brand token"),
    ("hicloud.net", "Huawei: a genuine dnstwist variant of icloud"),
    ("livee.com", "a genuine dnstwist variant of live.com"),
    ("microsoft-falcon.net", "Microsoft's own infrastructure, shaped like a combosquat"),
)


@dataclass(frozen=True, slots=True)
class Candidate:
    fqdn: str
    source: str
    suggestion: str | None = None
    brand: str | None = None
    note: str | None = None

    def to_json_line(self, today: date) -> str:
        """A dataset line with no label: `expected` is the reviewer's job."""
        payload = {
            "fqdn": self.fqdn,
            "expected": None,
            "suggestion": self.suggestion,
            "brand": self.brand,
            "source": self.source,
            "labelled_at": today.isoformat(),
            "note": self.note,
        }
        return json.dumps(payload, sort_keys=True)


def fetch_feed(url: str, timeout_s: float = 30.0) -> str:
    """Download a feed. The only network call in the evaluation code.

    Verification uses the OS trust store so a TLS-scanning antivirus or proxy does
    not break it, the same reason the classifier does.
    """
    import httpx

    from lookalike_hunter.classify.mistral import default_ssl_context

    # OpenPhish redirects its published feed to a mirror, so follow redirects.
    response = httpx.get(
        url, timeout=timeout_s, verify=default_ssl_context(), follow_redirects=True
    )
    response.raise_for_status()
    return response.text


def candidates_from_feed(
    feed_text: str, brands: Sequence[BrandConfig], source: str
) -> list[Candidate]:
    """Feed entries mentioning a configured Brand, as phishing candidates.

    The feed's own verdict is provenance, never ground truth: adopting it would
    measure agreement with the feed instead of accuracy.
    """
    entries: list[FeedEntry] = filter_to_brands(parse_url_feed(feed_text, source), brands)
    return [
        Candidate(
            fqdn=entry.fqdn,
            source=entry.source,
            suggestion="phishing",
            brand=entry.brand,
            note=f"listed by {entry.source}; confirm from the capture",
        )
        for entry in entries
    ]


def candidates_from_alerts(db_path: Path, limit: int) -> list[Candidate]:
    """Alerts with a successful Capture, which is what makes them reviewable.

    Drawn from what the pipeline actually meets, so the parked and legitimate
    classes reflect production rather than an idea of it.
    """
    if not db_path.exists():
        log.warning("dataset.no_database", db=str(db_path))
        return []
    with connect_with_retry(db_path, read_only=True) as con:
        rows = con.execute(
            """
            SELECT c.fqdn, arg_max(m.brand, m.score) AS brand, max(m.score) AS score
            FROM captures c
            JOIN matches m ON m.fqdn = c.fqdn
            WHERE c.status = 'ok' AND m.is_alert
            GROUP BY c.fqdn
            ORDER BY max(c.captured_at) DESC
            LIMIT ?
            """,
            [limit],
        ).fetchall()
    return [
        Candidate(
            fqdn=fqdn,
            source="alerts",
            suggestion=None,  # could be anything: that is the point of reviewing it
            brand=brand,
            note=f"alerted at score {score:.2f}; label from the screenshot",
        )
        for fqdn, brand, score in rows
    ]


def hard_negative_candidates() -> list[Candidate]:
    return [
        Candidate(fqdn=fqdn, source="calibration", suggestion="legitimate", note=note)
        for fqdn, note in KNOWN_HARD_NEGATIVES
    ]


def write_candidates(
    path: Path, candidates: Sequence[Candidate], today: date | None = None
) -> tuple[int, int]:
    """Append candidates not already present. Returns (added, skipped).

    Appending rather than rewriting protects labels already assigned: a rebuild
    must never silently discard a human's work.
    """
    existing: set[str] = set()
    if path.exists():
        existing = {site.fqdn for site in iter_dataset(path, allow_unlabelled=True)}

    stamp = today or datetime.now(UTC).date()
    added = 0
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        if not existing:
            handle.write(
                '# Candidate sites for evaluation. Set "expected" on every line;\n'
                "# see docs/labelling-protocol.md. Unlabelled entries are refused.\n"
            )
        for candidate in candidates:
            if candidate.fqdn in existing:
                continue
            handle.write(candidate.to_json_line(stamp) + "\n")
            existing.add(candidate.fqdn)
            added += 1
    return added, len(candidates) - added
