"""Compare captures of the same sites made from two Vantage points (P2.3).

Phishing kits often show a harmless page, or nothing, to cloud and scanner
addresses and the real page to ordinary visitors (cloaking). Capturing the same
site from two Vantage points and comparing the results shows how often that
happens to our own captures.

Read-only: nothing here writes to a database. Titles and URLs come from hostile
pages, so callers must print them through ``safe_text``.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from lookalike_hunter.ingest.store import connect_with_retry

# Phishing sites often live only hours. Captures further apart than this are not
# paired: "dead from one side" would mostly mean "taken down in between".
DEFAULT_MAX_GAP = timedelta(hours=6)


@dataclass(frozen=True, slots=True)
class SideCapture:
    """One capture as the comparison sees it."""

    fqdn: str
    captured_at: datetime
    status: str
    http_status: int | None = None
    final_host: str | None = None
    title: str | None = None
    has_login_form: bool = False
    # The latest verdict that is not an error, or None if the capture has none.
    verdict: str | None = None

    @property
    def reachable(self) -> bool:
        return self.status == "ok"


@dataclass(frozen=True, slots=True)
class SitePair:
    fqdn: str
    first: SideCapture
    second: SideCapture

    @property
    def unreachable_on_one_side(self) -> bool:
        return self.first.reachable != self.second.reachable

    @property
    def content_differences(self) -> tuple[str, ...]:
        """What differs between two loaded pages. Empty unless both sides loaded."""
        if not (self.first.reachable and self.second.reachable):
            return ()
        a, b = self.first, self.second
        checks = (
            ("http status", a.http_status != b.http_status),
            ("final site", a.final_host != b.final_host),
            ("login form", a.has_login_form != b.has_login_form),
            ("title", _norm(a.title) != _norm(b.title)),
        )
        return tuple(name for name, differs in checks if differs)

    @property
    def different_verdict(self) -> bool:
        """Both sides were judged and the judgements disagree."""
        a, b = self.first.verdict, self.second.verdict
        return a is not None and b is not None and a != b

    @property
    def differs(self) -> bool:
        return (
            self.unreachable_on_one_side or bool(self.content_differences) or self.different_verdict
        )


@dataclass(slots=True)
class CloakingReport:
    first_vantage: str
    second_vantage: str
    max_gap: timedelta
    pairs: list[SitePair] = field(default_factory=list)
    # Sites captured from both sides, but never within max_gap of each other.
    too_far_apart: int = 0
    only_first: int = 0
    only_second: int = 0

    @property
    def unreachable_on_one_side(self) -> int:
        return sum(p.unreachable_on_one_side for p in self.pairs)

    @property
    def different_content(self) -> int:
        return sum(bool(p.content_differences) for p in self.pairs)

    @property
    def different_verdict(self) -> int:
        return sum(p.different_verdict for p in self.pairs)

    @property
    def differing(self) -> list[SitePair]:
        return [p for p in self.pairs if p.differs]


def _norm(title: str | None) -> str:
    return " ".join((title or "").split()).casefold()


def _host(url: str | None) -> str | None:
    if not url:
        return None
    try:
        host = urlparse(url).hostname
    except ValueError:
        return None
    return host.lower() if host else None


def _page(signals: Any) -> tuple[str | None, bool]:
    """Title and login-form presence from stored signals, tolerant of odd shapes."""
    if not isinstance(signals, dict):
        return None, False
    title = signals.get("title")
    has_credential = bool(signals.get("has_password_input")) or bool(
        signals.get("has_credential_field")
    )
    form_count = signals.get("form_count")
    has_forms = isinstance(form_count, int) and form_count > 0
    return (title if isinstance(title, str) else None), has_credential and has_forms


def load_side(db_path: Path, vantage: str, backend: str | None) -> dict[str, list[SideCapture]]:
    """Every capture made from ``vantage``, grouped by hostname.

    The verdict attached to each capture is the latest non-error one, restricted to
    ``backend`` when given: verdicts from the offline stub and from a real model
    would otherwise disagree for reasons that have nothing to do with cloaking.
    """
    with connect_with_retry(db_path, read_only=True) as con:
        rows = con.execute(
            """
            SELECT c.fqdn, c.captured_at, c.status, c.http_status, c.final_url, c.signals,
                   (SELECT arg_max(v.label, v.classified_at) FROM verdicts v
                    WHERE v.capture_id = c.capture_id AND v.label <> 'error'
                      AND (? IS NULL OR v.backend = ?))
            FROM captures c
            WHERE c.vantage = ?
            """,
            [backend, backend, vantage],
        ).fetchall()
    side: dict[str, list[SideCapture]] = defaultdict(list)
    for fqdn, at, status, http_status, final_url, signals, verdict in rows:
        title, login = _page(json.loads(signals) if signals else None)
        side[fqdn].append(
            SideCapture(fqdn, at, status, http_status, _host(final_url), title, login, verdict)
        )
    return side


def compare(
    first: dict[str, list[SideCapture]],
    second: dict[str, list[SideCapture]],
    first_vantage: str,
    second_vantage: str,
    max_gap: timedelta = DEFAULT_MAX_GAP,
) -> CloakingReport:
    """Pair each site's two closest captures, one per side, if close enough in time."""
    report = CloakingReport(first_vantage, second_vantage, max_gap)
    report.only_first = len(first.keys() - second.keys())
    report.only_second = len(second.keys() - first.keys())
    for fqdn in sorted(first.keys() & second.keys()):
        a, b = min(
            ((a, b) for a in first[fqdn] for b in second[fqdn]),
            key=lambda pair: abs(pair[0].captured_at - pair[1].captured_at),
        )
        if abs(a.captured_at - b.captured_at) > max_gap:
            report.too_far_apart += 1
            continue
        report.pairs.append(SitePair(fqdn, a, b))
    return report
