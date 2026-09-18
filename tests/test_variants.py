from lookalike_hunter.config import BrandConfig
from lookalike_hunter.variants.generator import VariantIndex, generate_variants


def test_generate_variants_covers_main_fuzzers() -> None:
    variants = generate_variants("paypal.com", "paypal")
    domains = {v.domain for v in variants}
    fuzzers = {v.fuzzer for v in variants}

    assert "paypal.com" not in domains
    assert {"paypa.com", "papyal.com", "paypall.com"} <= domains  # omission/transposition/repeat
    assert any(d.startswith("xn--") for d in domains)  # IDN homoglyphs
    assert {"omission", "homoglyph", "transposition"} <= fuzzers


def test_index_excludes_official_domains_across_brand() -> None:
    # dnstwist's TLD swap of amazon.com would produce amazon.fr, which is official.
    brand = BrandConfig(
        name="amazon", tokens=["amazon"], official_domains=["amazon.com", "amazon.fr"]
    )
    index = VariantIndex.from_brands([brand], tlds=["fr", "xyz"])

    assert index.lookup("amazon.fr") == []
    assert index.lookup("amazom.com")[0].brand == "amazon"
    assert any(v.fuzzer == "tld-swap" for v in index.lookup("amazon.xyz"))
    assert index.lookup("AMAZOM.COM")  # case-insensitive


def test_lookup_miss() -> None:
    brand = BrandConfig(name="paypal", tokens=["paypal"], official_domains=["paypal.com"])
    assert VariantIndex.from_brands([brand]).lookup("example.org") == []
