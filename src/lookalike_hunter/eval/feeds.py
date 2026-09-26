"""Reading a public phishing feed into candidate sites.

Parsing is a pure function over text so it is tested against a recorded sample
rather than the live feed, which changes hourly.

The brand filter here deliberately does **not** use the Scorer. Selecting feed
entries with our own detector would make recall meaningless: the dataset would
contain only phishing we already catch, and recall would be 100% by construction.
Instead a plain, case-insensitive substring search runs over the whole URL,
including the path. `secure-verify.example/paypal/signin` has no brand token in its
hostname, so the Scorer cannot see it -- and it belongs in the dataset precisely
because missing it is a real miss.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from urllib.parse import urlparse

from lookalike_hunter.capture.policy import is_valid_hostname
from lookalike_hunter.config import BrandConfig

OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"


@dataclass(frozen=True, slots=True)
class FeedEntry:
    fqdn: str
    url: str
    source: str
    brand: str | None = None


def parse_url_feed(text: str, source: str) -> list[FeedEntry]:
    """Parse a feed of one URL per line (OpenPhish free feed format).

    Entries that are not plain http(s) URLs with a usable hostname are dropped:
    a feed is third-party input and may contain anything.
    """
    entries: list[FeedEntry] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parsed = urlparse(line)
        if parsed.scheme not in {"http", "https"}:
            continue
        host = (parsed.hostname or "").strip().lower()
        if not host or not is_valid_hostname(host) or host in seen:
            continue
        seen.add(host)
        entries.append(FeedEntry(fqdn=host, url=line, source=source))
    return entries


def brand_for_url(url: str, brands: Sequence[BrandConfig]) -> str | None:
    """The Brand a URL mentions anywhere, by plain substring, or None.

    Intentionally naive: no Skeleton, no homoglyph folding, no edit distance. Those
    belong to the detector being measured, not to the selection of what to measure.
    """
    haystack = url.lower()
    for brand in brands:
        if any(token in haystack for token in brand.tokens):
            return brand.name
    return None


def filter_to_brands(
    entries: Iterable[FeedEntry], brands: Sequence[BrandConfig]
) -> list[FeedEntry]:
    """Keep entries mentioning a configured Brand, recording which one."""
    kept: list[FeedEntry] = []
    for entry in entries:
        brand = brand_for_url(entry.url, brands)
        if brand is not None:
            kept.append(FeedEntry(fqdn=entry.fqdn, url=entry.url, source=entry.source, brand=brand))
    return kept
