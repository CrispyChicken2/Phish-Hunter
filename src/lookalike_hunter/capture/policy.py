"""What the capture browser is allowed to touch.

Defensive tooling visits hostile pages, so the page must not be able to steer the
browser somewhere sensitive. A redirect or a sub-resource pointing at 127.0.0.1,
192.168.x.x or the cloud metadata address 169.254.169.254 would make our own
browser probe the operator's network; those are refused before the request is made.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

ALLOWED_SCHEMES = frozenset({"http", "https"})

# A certificate SAN is attacker-controlled text, not necessarily a hostname. Left
# unchecked, "evil.com@router.local" builds a URL whose real host is router.local
# (the part before @ is userinfo), so we would visit a host we did not intend and
# file the evidence under the wrong name.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9_])?"
    r"(?:\.[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9_])?)*\.?$"
)

_PORT_RE = re.compile(r"^:(?:[1-9][0-9]{0,4})$")

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


def is_valid_hostname(host: str) -> bool:
    """True for a plain DNS hostname or IP, with an optional :port.

    Rejects userinfo, paths, spaces and anything else that would make the URL
    resolve to a different host than the one we recorded. A port is harmless: the
    host part is still validated and private addresses are still refused.
    """
    host = host.lower()
    if host.startswith("["):  # bracketed IPv6 literal, optionally with a port
        literal, bracket, port = host.partition("]")
        if not bracket or (port and not _PORT_RE.match(port)):
            return False
        try:
            ipaddress.ip_address(literal[1:])
        except ValueError:
            return False
        return True
    name, sep, port = host.rpartition(":")
    if sep:
        if not _PORT_RE.match(f":{port}"):
            return False
    else:
        name = host
    try:  # a bare IP literal is a valid target
        ipaddress.ip_address(name)
    except ValueError:
        return bool(_HOSTNAME_RE.match(name))
    return True


def candidate_urls(fqdn: str) -> list[str]:
    """URLs to try for a hostname: HTTPS first, then HTTP.

    The certificate proves HTTPS is configured, but phishing kits are often served
    over plain HTTP from the same host, so a failure on 443 is worth one retry.
    """
    return [f"https://{fqdn}/", f"http://{fqdn}/"]
