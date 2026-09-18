"""Pre-computed lookalike Variants per Brand, using dnstwist fuzzers offline.

dnstwist is used purely as a permutation engine: no DNS, WHOIS or HTTP lookups.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

import dnstwist

from lookalike_hunter.config import BrandConfig


@dataclass(frozen=True, slots=True)
class Variant:
    domain: str
    brand: str
    fuzzer: str


def generate_variants(official_domain: str, brand: str, tlds: Iterable[str] = ()) -> list[Variant]:
    """All dnstwist permutations of ``official_domain`` except the original itself.

    ``tlds`` enables the ``tld-swap`` fuzzer (e.g. ``["net", "co", "info"]``).
    """
    fuzzer = dnstwist.Fuzzer(official_domain.lower(), tld_dictionary=list(tlds))
    fuzzer.generate()
    return [
        Variant(domain=entry["domain"], brand=brand, fuzzer=entry["fuzzer"])
        for entry in fuzzer.domains
        if entry["fuzzer"] != "*original" and entry["domain"] != official_domain.lower()
    ]


class VariantIndex:
    """Exact-match lookup from registered domain to the Variant(s) it matches."""

    def __init__(self, variants: Iterable[Variant]) -> None:
        self._by_domain: dict[str, list[Variant]] = {}
        for variant in variants:
            self._by_domain.setdefault(variant.domain, []).append(variant)

    @classmethod
    def from_brands(cls, brands: Iterable[BrandConfig], tlds: Iterable[str] = ()) -> VariantIndex:
        tld_list = list(tlds)
        variants: list[Variant] = []
        for brand in brands:
            official = set(brand.official_domains)
            for domain in brand.official_domains:
                variants.extend(
                    v
                    for v in generate_variants(domain, brand.name, tld_list)
                    if v.domain not in official
                )
        return cls(variants)

    def lookup(self, registered_domain: str) -> list[Variant]:
        return self._by_domain.get(registered_domain.lower(), [])

    def __len__(self) -> int:
        return len(self._by_domain)
