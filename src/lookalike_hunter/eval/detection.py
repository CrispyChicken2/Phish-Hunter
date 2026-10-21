"""Would our scoring have caught known phishing? Feed entries against our own Matches.

A phishing feed lists sites that are phishing by someone else's account. Comparing
those with the Matches our certificate scoring stored answers the question the
project exists for: of real phishing, how much did we flag, and was it before the
feed listed it.

One limit is structural, not a weakness of the scorer: a site on a shared platform
(``*.vercel.app``, ``*.github.io``...) is served under the platform's wildcard
certificate, so no certificate ever names it and certificate monitoring cannot see
it. Those sites are counted apart, as out of reach, rather than as misses.

Read-only. Feed entries stay outside git (docs/feed-data.md); this prints counts.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date, datetime
from enum import StrEnum
from pathlib import Path

import tldextract

from lookalike_hunter.eval.dataset import LabelledSite, iter_dataset
from lookalike_hunter.ingest.store import connect_with_retry

# Private suffixes on: they are how a shared platform is recognised.
_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)


class Outcome(StrEnum):
    ALERTED = "alerted"  # a Match at or above the alert threshold
    MATCHED = "matched"  # stored, but scored below the alert threshold
    NOT_SEEN = "not seen"  # no Match at all
    OUT_OF_REACH = "out of reach"  # shared platform, and no Match either


class Timing(StrEnum):
    BEFORE = "before the listing day"
    SAME_DAY = "on the listing day"
    AFTER = "after the listing day"


@dataclass(frozen=True, slots=True)
class FeedSite:
    fqdn: str
    listed_on: date
    shared_platform: bool
    outcome: Outcome
    first_flagged: datetime | None = None

    @property
    def timing(self) -> Timing | None:
        if self.first_flagged is None:
            return None
        flagged_on = self.first_flagged.date()
        if flagged_on < self.listed_on:
            return Timing.BEFORE
        return Timing.SAME_DAY if flagged_on == self.listed_on else Timing.AFTER


@dataclass(slots=True)
class DetectionReport:
    sites: list[FeedSite] = field(default_factory=list)
    monitoring_since: date | None = None
    # Listed before monitoring began: a miss there says nothing about the scorer.
    listed_before_monitoring: int = 0

    def count(self, outcome: Outcome) -> int:
        return sum(site.outcome is outcome for site in self.sites)

    @property
    def in_reach(self) -> int:
        return len(self.sites) - self.count(Outcome.OUT_OF_REACH)

    def timing(self, timing: Timing) -> int:
        return sum(site.outcome is Outcome.ALERTED and site.timing is timing for site in self.sites)


def shared_platform(fqdn: str) -> bool:
    """Hosted under a private public suffix, i.e. a platform's wildcard certificate."""
    return bool(_EXTRACT(fqdn).is_private)


def _registered(fqdn: str) -> str:
    """The domain a registrant buys, as the scorer stores it. Not for shared platforms."""
    ext = _EXTRACT(fqdn)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else fqdn


def _first_listing(entries: Iterable[LabelledSite]) -> dict[str, date]:
    listed: dict[str, date] = {}
    for entry in entries:
        if entry.fqdn not in listed or entry.labelled_at < listed[entry.fqdn]:
            listed[entry.fqdn] = entry.labelled_at
    return listed


def feed_detection(feed_entries_path: Path, db_path: Path) -> DetectionReport:
    """Classify every Feed entry by what our scoring did with it."""
    listed = _first_listing(iter_dataset(feed_entries_path, allow_unlabelled=True))
    with connect_with_retry(db_path, read_only=True) as con:
        row = con.execute("SELECT min(first_seen_at) FROM matches").fetchone()
        since = row[0].date() if row and row[0] else None
        report = DetectionReport(monitoring_since=since)
        for fqdn, listed_on in sorted(listed.items()):
            if since is None or listed_on < since:
                report.listed_before_monitoring += 1
                continue
            shared = shared_platform(fqdn)
            # A shared-platform site only counts when our Match names that very host:
            # its registered domain is the platform's, shared with everyone else on it.
            found = con.execute(
                """
                SELECT bool_or(is_alert),
                       coalesce(min(first_seen_at) FILTER (WHERE is_alert), min(first_seen_at))
                FROM matches
                WHERE fqdn = ? OR (? AND registered_domain = ?)
                """,
                [fqdn, not shared, _registered(fqdn)],
            ).fetchone()
            alerted, first = found if found else (None, None)
            if alerted is None:
                outcome = Outcome.OUT_OF_REACH if shared else Outcome.NOT_SEEN
            else:
                outcome = Outcome.ALERTED if alerted else Outcome.MATCHED
            report.sites.append(FeedSite(fqdn, listed_on, shared, outcome, first))
    return report
