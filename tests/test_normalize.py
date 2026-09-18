import pytest

from lookalike_hunter.scoring.normalize import decode_idna, skeleton


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("PayPal.com", "paypal.com"),
        ("paypa1.com", "paypal.com"),
        ("rnicrosoft.com", "microsoft.com"),
        ("vvebmail.com", "webmail.com"),
        ("аррӏе.com", "apple.com"),  # Cyrillic а, р, р, palochka, е
        ("amazön.fr", "amazon.fr"),
        ("netf1ix-l0gin.net", "netflix-login.net"),
    ],
)
def test_skeleton_collapses_confusables(raw: str, expected: str) -> None:
    assert skeleton(raw) == expected


def test_decode_idna_handles_punycode() -> None:
    assert decode_idna("xn--pypal-4ve.com") == "pаypal.com"


def test_decode_idna_keeps_invalid_labels() -> None:
    assert decode_idna("xn--99999999.com") == "xn--99999999.com"


def test_skeleton_decodes_punycode_first() -> None:
    assert skeleton("xn--pypal-4ve.com") == "paypal.com"
