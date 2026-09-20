"""Hostname normalisation: punycode decoding and confusable-character skeletons.

Two levels, because aggressiveness that is safe when comparing whole words is unsafe
when searching for a token *inside* a longer word:

* :func:`skeleton` only collapses characters that are already unambiguous lookalikes
  (Cyrillic ``а`` -> ``a``, ``1`` -> ``l``). Safe for substring search.
* :func:`loose_skeleton` also collapses ``i``/``l`` and multi-character sequences
  (``rn`` -> ``m``). These *create* letters, so ``hummel`` + ``cloud`` would contain
  ``lcloud`` (i.e. ``icloud``). Only compare whole words with it, never substrings.

Both are lossy: compare skeleton to skeleton, and never store one as an identity.
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

# Loose-only: "i" and "l" render alike, but collapsing them turns the "l" ending
# innocent words into the "i" of a brand token ("hummelcloud" -> "icloud").
_LOOSE_CHAR_MAP: dict[str, str] = {"i": "l"}

# Multi-character sequences that render like a single letter. Loose-only for the
# same reason: they create letters the original text did not have.
# ``cl`` -> ``d`` is deliberately absent: it rewrites every ``cloud`` and caused
# false positives against ``icloud`` on live CT data.
_LOOSE_SEQ_MAP: tuple[tuple[str, str], ...] = (("rn", "m"), ("vv", "w"))

_TRANSLATION = str.maketrans(_CHAR_MAP)
_LOOSE_TRANSLATION = str.maketrans(_CHAR_MAP | _LOOSE_CHAR_MAP)


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
    """Collapse unambiguous confusables only. Safe to search inside longer words."""
    return _strip_diacritics(decode_idna(hostname)).lower().translate(_TRANSLATION)


def loose_skeleton(hostname: str) -> str:
    """Also collapse i/l and rn/vv sequences. Only compare whole words with this."""
    text = _strip_diacritics(decode_idna(hostname)).lower().translate(_LOOSE_TRANSLATION)
    for seq, repl in _LOOSE_SEQ_MAP:
        text = text.replace(seq, repl)
    return text
