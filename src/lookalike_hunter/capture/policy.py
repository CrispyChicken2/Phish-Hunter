"""What the capture browser is allowed to touch.

Defensive tooling visits hostile pages, so the page must not be able to steer the
browser somewhere sensitive. A redirect or a sub-resource pointing at 127.0.0.1,
192.168.x.x or the cloud metadata address 169.254.169.254 would make our own
browser probe the operator's network; those are refused before the request is made.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

ALLOWED_SCHEMES = frozenset({"http", "https"})

# Schemes a page may legitimately reference and that never reach the network.
INERT_SCHEMES = frozenset({"data", "blob", "about", "javascript"})


def is_private_address(host: str) -> bool:
    """True for a literal IP that is loopback, private, link-local or reserved.

    Hostnames return False: they are resolved separately, since the DNS answer is
    what actually decides where the request goes.
    """
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def is_blocked_url(url: str, *, block_private_networks: bool = True) -> str | None:
    """Return a reason to refuse this URL, or None when it may be requested."""
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme in INERT_SCHEMES:
        return None
    if scheme not in ALLOWED_SCHEMES:
        return f"scheme {scheme or '(none)'} not allowed"
    host = parsed.hostname
    if not host:
        return "no host"
    if block_private_networks and is_private_address(host):
        return f"private address {host}"
    return None


def candidate_urls(fqdn: str) -> list[str]:
    """URLs to try for a hostname: HTTPS first, then HTTP.

    The certificate proves HTTPS is configured, but phishing kits are often served
    over plain HTTP from the same host, so a failure on 443 is worth one retry.
    """
    return [f"https://{fqdn}/", f"http://{fqdn}/"]
