"""Hostname normalisation: punycode decoding and confusable-character skeletons.

The skeleton is intentionally lossy (``rn`` -> ``m`` also rewrites ``modern``). It is
only meaningful when both sides of a comparison are skeletonised, so brand tokens
go through :func:`skeleton` too. Never store it as an identity.
"""

from __future__ import annotations

import contextlib
import unicodedata

# Single-codepoint confusables not handled by NFKD diacritic stripping.
# Cyrillic/Greek lookalikes plus the classic digit substitutions.
_CHAR_MAP: dict[str, str] = {
    # Cyrillic
    "а": "a", "в": "b", "с": "c", "ԁ": "d", "е": "e", "һ": "h", "і": "i", "ј": "j",
    "к": "k", "ӏ": "l", "м": "m", "п": "n", "о": "o", "р": "p", "ԛ": "q", "г": "r",
    "ѕ": "s", "т": "t", "ц": "u", "ѵ": "v", "ԝ": "w", "х": "x", "у": "y", "ʐ": "z",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
    "τ": "t", "υ": "u", "χ": "x",
    # Latin extras
    "ı": "i", "ł": "l", "ø": "o", "đ": "d", "ħ": "h", "ɡ": "g",
    # Digits
    "0": "o", "1": "l", "3": "e", "5": "s",
}  # fmt: skip

# Multi-character sequences that render like a single letter. Applied after the
# character map, longest first.
# ``cl`` -> ``d`` is deliberately absent: it rewrites every ``cloud`` and caused
# false positives against ``icloud`` on live CT data.
_SEQ_MAP: tuple[tuple[str, str], ...] = (("rn", "m"), ("vv", "w"))

_TRANSLATION = str.maketrans(_CHAR_MAP)


def decode_idna(hostname: str) -> str:
    """Decode ``xn--`` labels to Unicode; labels that fail to decode are kept as-is."""
    labels = []
    for label in hostname.lower().split("."):
        if label.startswith("xn--"):
            with contextlib.suppress(UnicodeError):
                label = label[4:].encode("ascii").decode("punycode")
        labels.append(label)
    return ".".join(labels)


def _strip_diacritics(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(c for c in decomposed if not unicodedata.combining(c))


def skeleton(hostname: str) -> str:
    """Return the confusable-collapsed ASCII-ish skeleton of a hostname."""
    text = _strip_diacritics(decode_idna(hostname)).lower().translate(_TRANSLATION)
    for seq, repl in _SEQ_MAP:
        text = text.replace(seq, repl)
    return text
