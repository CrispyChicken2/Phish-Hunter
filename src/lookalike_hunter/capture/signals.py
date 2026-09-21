"""Extract phishing-relevant signals from captured HTML.

A pure function over a string: no browser, no network, so it is cheap to test and
can be re-run on stored captures when the heuristics change. These signals are
given to the classifier alongside the screenshot.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlparse

import tldextract

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_CREDENTIAL_NAMES = ("password", "passwd", "pwd", "pin", "otp", "mdp", "motdepasse")


@dataclass(frozen=True, slots=True)
class PageSignals:
    title: str | None = None
    form_count: int = 0
    has_password_input: bool = False
    # A credential-looking field name even without type="password" (kits hide them).
    has_credential_field: bool = False
    # Forms posting to another registered domain: classic credential exfiltration.
    cross_domain_form_targets: list[str] = field(default_factory=list)
    iframe_count: int = 0
    password_input_count: int = 0

    @property
    def has_login_form(self) -> bool:
        return (self.has_password_input or self.has_credential_field) and self.form_count > 0


class _SignalParser(HTMLParser):
    def __init__(self, page_domain: str) -> None:
        super().__init__(convert_charrefs=True)
        self.page_domain = page_domain
        self.title: str | None = None
        self.form_count = 0
        self.password_inputs = 0
        self.credential_field = False
        self.iframes = 0
        self.form_targets: list[str] = []
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "iframe":
            self.iframes += 1
        elif tag == "form":
            self.form_count += 1
            self._record_action(attr.get("action", ""))
        elif tag == "input":
            if attr.get("type", "").lower() == "password":
                self.password_inputs += 1
            haystack = f"{attr.get('name', '')} {attr.get('id', '')}".lower()
            if any(n in haystack for n in _CREDENTIAL_NAMES):
                self.credential_field = True

    def _record_action(self, action: str) -> None:
        if not action:
            return
        host = urlparse(action).hostname
        if not host:
            return  # relative action: same site
        ext = _EXTRACT(host)
        registered = f"{ext.domain}.{ext.suffix}" if ext.suffix else host
        if registered != self.page_domain and registered not in self.form_targets:
            self.form_targets.append(registered)

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and self.title is None and data.strip():
            self.title = data.strip()[:300]


def extract_signals(html: str, page_url: str) -> PageSignals:
    """Parse ``html`` for login-form and exfiltration signals. Never raises."""
    ext = _EXTRACT(urlparse(page_url).hostname or "")
    page_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ""
    parser = _SignalParser(page_domain)
    parser.feed(html)
    parser.close()
    return PageSignals(
        title=parser.title,
        form_count=parser.form_count,
        has_password_input=parser.password_inputs > 0,
        has_credential_field=parser.credential_field,
        cross_domain_form_targets=parser.form_targets,
        iframe_count=parser.iframes,
        password_input_count=parser.password_inputs,
    )
