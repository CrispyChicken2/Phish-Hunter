import pytest

from lookalike_hunter.scoring.normalize import decode_idna, loose_skeleton, skeleton


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("PayPal.com", "paypal.com"),
        ("paypa1.com", "paypal.com"),
        ("аррӏе.com", "apple.com"),  # Cyrillic а, р, р, palochka, е
        ("amazön.fr", "amazon.fr"),
        ("netf1ix-l0gin.net", "netflix-login.net"),
    ],
)
def test_skeleton_collapses_confusables(raw: str, expected: str) -> None:
    # The skeleton form itself is an implementation detail; equivalence is the contract.
    assert skeleton(raw) == skeleton(expected)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("lcloud.com", "icloud.com"),
        ("rnicrosoft.com", "microsoft.com"),
        ("vvebmail.com", "webmail.com"),
        ("paypa1.com", "paypal.com"),  # everything skeleton() does, loose does too
    ],
)
def test_loose_skeleton_collapses_letter_creating_confusables(raw: str, expected: str) -> None:
    assert loose_skeleton(raw) == loose_skeleton(expected)


@pytest.mark.parametrize("raw", ["hummelcloud.net", "vercelcloud.com", "bigbullcloud.com"])
def test_skeleton_does_not_invent_brand_tokens(raw: str) -> None:
    # The whole point of the conservative level: these must not contain "icloud".
    assert skeleton("icloud") not in skeleton(raw)
    assert loose_skeleton("icloud") in loose_skeleton(raw)  # why loose is substring-unsafe


def test_decode_idna_handles_punycode() -> None:
    assert decode_idna("xn--pypal-4ve.com") == "pаypal.com"


def test_decode_idna_keeps_invalid_labels() -> None:
    assert decode_idna("xn--99999999.com") == "xn--99999999.com"


def test_skeleton_decodes_punycode_first() -> None:
    assert skeleton("xn--pypal-4ve.com") == "paypal.com"


def test_skeleton_keeps_unrelated_words_apart() -> None:
    assert skeleton("cloud") != skeleton("icloud")
    assert skeleton("paypal") != skeleton("paypai-x")
