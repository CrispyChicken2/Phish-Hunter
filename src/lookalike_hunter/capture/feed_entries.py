"""Fresh Feed entries for the watch loop to capture (P2.1).

The feed timer only appends new Feed entries to a file (unlabelled dataset lines). The
watch loop captures them, a few per cycle, so there is still one process, one browser
and one database writer on the instance. Phishing kits are often gone within hours, so
only recently listed entries are worth a visit; the newest go first, and each site is
visited once.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from lookalike_hunter.eval.dataset import iter_dataset
from lookalike_hunter.ingest.store import MatchStore, PendingCapture

# A feed site is captured once: a page that was down or dead is not retried, so the
# per-cycle budget always goes to the newest entries. About a century, in hours.
NEVER_RECAPTURE_H = 24 * 365 * 100


def fresh_feed_targets(
    store: MatchStore,
    feed_entries_path: Path,
    limit: int,
    max_age_days: int,
    today: date | None = None,
) -> list[PendingCapture]:
    """Candidates listed in the last ``max_age_days`` days and never captured, newest first.

    A missing file is not an error: the feed timer may not have run yet.
    """
    if limit <= 0 or not feed_entries_path.exists():
        return []
    oldest = (today or datetime.now(UTC).date()) - timedelta(days=max_age_days)
    sites = [
        site
        for site in iter_dataset(feed_entries_path, allow_unlabelled=True)
        if site.labelled_at >= oldest
    ]
    # The timer appends, so the newest candidates are at the end of the file.
    newest_first = {site.fqdn: site for site in reversed(sites)}
    todo = store.uncaptured(list(newest_first), NEVER_RECAPTURE_H)[:limit]
    return [
        PendingCapture(
            fqdn=fqdn,
            registered_domain=fqdn,
            brand=newest_first[fqdn].brand or "",
            score=0.0,
        )
        for fqdn in todo
    ]
