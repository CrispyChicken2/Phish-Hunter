from pathlib import Path

import pytest

from lookalike_hunter.config import load_settings
from lookalike_hunter.scoring.scorer import Scorer, normalize_hostname
from lookalike_hunter.variants.generator import VariantIndex

DEFAULT = Path(__file__).parents[1] / "configs" / "default.yaml"


@pytest.fixture(scope="module")
def scorer() -> Scorer:
    settings = load_settings(DEFAULT)
    index = VariantIndex.from_brands(settings.brands, settings.variants.swap_tlds)
    return Scorer(settings.brands, settings.scoring, index)


def top_score(scorer: Scorer, fqdn: str, issuer: str | None = None) -> float:
    matches = scorer.score(fqdn, issuer)
    return max((m.score for m in matches), default=0.0)


@pytest.mark.parametrize(
    "fqdn",
    [
        "paypal.com",
        "www.paypal.com",
        "login.microsoftonline.com",
        "pineapple-recipes.com",
        "google.com",
        "amelia-bakery.fr",
        "applebees-menu.com",
        # Regressions found on live CT data:
        "status.doubleu-cloud.de",
        "x.europe-west4.managedkafka.cloud.goog",
        "app14.shop",
        # "<word ending in l>cloud" must not read as "icloud":
        "hummelcloud.net",
        "bigbullcloud.com",
        "vercelcloud.com",
        "app-x.loca-5823.vesselcloud.dev",
        "voxelclouddao.xyz",
        # "xiamei1" must not read as "ameli":
        "nongminboboxiangxiamei1.com.cn",
        "tiarneliu.com",
        # rn -> m inside a longer word must not read as "ameli" either:
        "ateliergamelle.com",
        "thedarnells.org",
        "thehouseofjameillajenell.com",
        "jailynparnell.com",
    ],
)
def test_benign_hostnames_are_not_alerts(scorer: Scorer, fqdn: str) -> None:
    assert top_score(scorer, fqdn) < 0.7


@pytest.mark.parametrize(
    "fqdn",
    [
        "paypa1.com",  # digit homoglyph
        "xn--pypal-4ve.com",  # Cyrillic a (IDN homoglyph)
        "paypall.com",  # repetition typo
        "paypal-secure-login.xyz",  # combosquat
        "paypal.com.account-verify.top",  # brand in subdomain
        "rnicrosoft-support.net",  # rn -> m
        "netflix.shop",  # TLD swap
        "ameli-remboursement.fr",
        # Whole-word confusables must still be caught (live CT data):
        "lcloud-localizado.info",  # i/l swap, whole label part
        "lcloud-ubicacion-com.help",
        "appleid-security.com",
    ],
)
def test_lookalikes_are_alerts(scorer: Scorer, fqdn: str) -> None:
    assert top_score(scorer, fqdn) >= 0.7


def test_known_variant_outranks_plain_combosquat(scorer: Scorer) -> None:
    assert top_score(scorer, "paypa.com") > top_score(scorer, "paypal-shop.com")


def test_features_explain_the_score(scorer: Scorer) -> None:
    (match,) = scorer.score("xn--pypal-4ve.com", "Let's Encrypt")
    assert match.brand == "paypal"
    assert match.registered_domain == "xn--pypal-4ve.com"
    assert match.features.homoglyph
    assert match.features.free_dv_issuer

    (variant,) = scorer.score("paypa.com")
    assert variant.features.known_variant_fuzzers == ["omission"]


def test_keywords_survive_skeleton(scorer: Scorer) -> None:
    (match,) = scorer.score("icloud-verify-signin.live")
    assert set(match.features.keyword_hits) == {"verify", "signin"}


def test_keywords_increase_score(scorer: Scorer) -> None:
    assert top_score(scorer, "paypal-login-verify.com") > top_score(scorer, "paypal-shop.com")


def test_short_token_needs_whole_part() -> None:
    settings = load_settings(DEFAULT)
    brand = settings.brands[0].model_copy(
        update={"name": "dhl", "tokens": ["dhl"], "official_domains": ["dhl.com"]}
    )
    s = Scorer([brand], settings.scoring, VariantIndex([]))
    assert top_score(s, "dhl-tracking.com") >= 0.6
    assert top_score(s, "adhlocal.com") == 0.0


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("*.PayPal-Login.com.", "paypal-login.com"), ("  a.b.com", "a.b.com"), ("*.", None)],
)
def test_normalize_hostname(raw: str, expected: str | None) -> None:
    assert normalize_hostname(raw) == expected
