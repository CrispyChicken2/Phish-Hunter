"""Score a Candidate hostname against every Brand.

The score is an explainable, hand-weighted combination of features:

* a *base* signal saying *why* the hostname relates to the brand (known Variant,
  typo of a token, token in the registered label, token in the subdomain) — the
  strongest one wins;
* small additive *bonuses* (homoglyph use, sensitive keywords, free DV issuer).

Keywords and bonuses never create a Match on their own: without a base signal the
hostname is unrelated to the brand.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

import tldextract
from rapidfuzz.distance import DamerauLevenshtein

from lookalike_hunter.config import BrandConfig, ScoringConfig
from lookalike_hunter.scoring.normalize import decode_idna, skeleton
from lookalike_hunter.variants.generator import Variant, VariantIndex

_PART_SPLIT = re.compile(r"[^a-z]+")

# Bundled Public Suffix List snapshot only: no network fetch at runtime.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


@dataclass(frozen=True, slots=True)
class MatchFeatures:
    known_variant_fuzzers: list[str] = field(default_factory=list)
    typo_similarity: float = 0.0
    token_in_registered_label: bool = False
    token_in_subdomain: bool = False
    homoglyph: bool = False
    keyword_hits: list[str] = field(default_factory=list)
    free_dv_issuer: bool = False


@dataclass(frozen=True, slots=True)
class Match:
    fqdn: str
    registered_domain: str
    brand: str
    score: float
    features: MatchFeatures


def normalize_hostname(raw: str) -> str | None:
    """Lowercase, strip whitespace, wildcard prefix and trailing dot. None if empty."""
    host = raw.strip().lower().removeprefix("*.").rstrip(".")
    return host or None


@dataclass(frozen=True)
class _Host:
    fqdn: str
    registered_domain: str
    label_sk: str  # skeleton of the registrable label ("paypal" in paypal.co.uk)
    subdomain_sk: str
    label_raw: str  # Unicode-decoded, before confusable collapsing
    subdomain_raw: str


class _BrandMatcher:
    def __init__(self, brand: BrandConfig, config: ScoringConfig) -> None:
        self.brand = brand
        self.official = frozenset(brand.official_domains)
        self.tokens = [skeleton(t) for t in brand.tokens]
        self.raw_tokens = brand.tokens
        self.negatives = [skeleton(t) for t in brand.negative_tokens]
        self.min_len = config.min_substring_token_len

    def strip_negatives(self, text: str) -> str:
        for neg in self.negatives:
            text = text.replace(neg, " ")
        return text

    def contains_token(self, text: str, tokens: Sequence[str]) -> bool:
        text = self.strip_negatives(text)
        parts = set(_PART_SPLIT.split(text))
        return any((t in text) if len(t) >= self.min_len else (t in parts) for t in tokens)

    def typo_similarity(self, host: _Host) -> float:
        label = self.strip_negatives(host.label_sk)
        candidates = {label, *_PART_SPLIT.split(label)}
        return max(
            (
                DamerauLevenshtein.normalized_similarity(part, token)
                for part in candidates
                for token in self.tokens
                if part.strip()
            ),
            default=0.0,
        )


class Scorer:
    def __init__(
        self,
        brands: Iterable[BrandConfig],
        config: ScoringConfig,
        variants: VariantIndex,
    ) -> None:
        self._config = config
        self._matchers = [_BrandMatcher(b, config) for b in brands]
        self._variants = variants
        self._keywords = [k.lower() for k in config.sensitive_keywords]
        self._free_dv = [i.lower() for i in config.free_dv_issuers]

    def score(self, raw_hostname: str, issuer_org: str | None = None) -> list[Match]:
        """Return one Match per Brand whose score is at least the storage floor."""
        host = self._parse(raw_hostname)
        if host is None:
            return []
        variant_hits = self._variants.lookup(host.registered_domain)
        free_dv = issuer_org is not None and any(i in issuer_org.lower() for i in self._free_dv)
        full_sk = f"{host.subdomain_sk}.{host.label_sk}"

        matches: list[Match] = []
        for m in self._matchers:
            if host.registered_domain in m.official:
                continue
            features = self._features(host, m, variant_hits, free_dv, full_sk)
            score = self._combine(features)
            if score >= self._config.store_floor:
                matches.append(
                    Match(host.fqdn, host.registered_domain, m.brand.name, score, features)
                )
        return matches

    @staticmethod
    def _parse(raw_hostname: str) -> _Host | None:
        fqdn = normalize_hostname(raw_hostname)
        if fqdn is None:
            return None
        ext = _EXTRACT(fqdn)
        if not ext.suffix or not ext.domain:
            return None
        registered = f"{ext.domain}.{ext.suffix}"
        return _Host(
            fqdn=fqdn,
            registered_domain=registered,
            label_sk=skeleton(ext.domain),
            subdomain_sk=skeleton(ext.subdomain),
            label_raw=decode_idna(ext.domain),
            subdomain_raw=decode_idna(ext.subdomain),
        )

    def _features(
        self,
        host: _Host,
        m: _BrandMatcher,
        variant_hits: Sequence[Variant],
        free_dv: bool,
        full_sk: str,
    ) -> MatchFeatures:
        fuzzers = sorted({v.fuzzer for v in variant_hits if v.brand == m.brand.name})
        in_label = m.contains_token(host.label_sk, m.tokens)
        in_sub = m.contains_token(host.subdomain_sk, m.tokens)
        homoglyph = (in_label or in_sub) and not (
            m.contains_token(host.label_raw, m.raw_tokens)
            or m.contains_token(host.subdomain_raw, m.raw_tokens)
        )
        stripped = full_sk
        for token in m.tokens:
            stripped = stripped.replace(token, " ")
        keywords = [k for k in self._keywords if k in stripped]
        return MatchFeatures(
            known_variant_fuzzers=fuzzers,
            typo_similarity=round(m.typo_similarity(host), 4),
            token_in_registered_label=in_label,
            token_in_subdomain=in_sub,
            homoglyph=homoglyph,
            keyword_hits=keywords,
            free_dv_issuer=free_dv,
        )

    def _combine(self, f: MatchFeatures) -> float:
        w = self._config.weights
        typo = (
            w.typo_similarity * f.typo_similarity
            if self._config.min_typo_similarity <= f.typo_similarity < 1.0
            else 0.0
        )
        base = max(
            w.known_variant if f.known_variant_fuzzers else 0.0,
            typo,
            w.token_in_registered_label if f.token_in_registered_label else 0.0,
            w.token_in_subdomain if f.token_in_subdomain else 0.0,
        )
        if base == 0.0:
            return 0.0
        bonus = (
            (w.homoglyph_bonus if f.homoglyph else 0.0)
            + w.keyword_bonus * min(len(f.keyword_hits), w.max_keyword_hits)
            + (w.free_dv_bonus if f.free_dv_issuer else 0.0)
        )
        return round(min(1.0, base + bonus), 4)
