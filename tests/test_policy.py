import pytest

from lookalike_hunter.capture.policy import (
    candidate_urls,
    is_blocked_url,
    is_private_address,
    is_valid_hostname,
)


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "0.0.0.0",
        "10.1.2.3",
        "192.168.1.1",
        "172.16.0.5",
        "169.254.169.254",  # cloud metadata
        "::1",
        "[::1]",
        "fd00::1",
    ],
)
def test_private_addresses_are_detected(host: str) -> None:
    assert is_private_address(host)


@pytest.mark.parametrize("host", ["8.8.8.8", "1.1.1.1", "2606:4700::1111", "example.com"])
def test_public_addresses_and_names_are_not_private(host: str) -> None:
    assert not is_private_address(host)


@pytest.mark.parametrize(
    ("url", "reason_fragment"),
    [
        ("http://127.0.0.1:8080/admin", "private address"),
        ("https://192.168.0.1/", "private address"),
        ("http://[::1]/", "private address"),
        ("file:///c:/windows/system32/drivers/etc/hosts", "scheme file"),
        ("ftp://example.com/x", "scheme ftp"),
        ("chrome://settings", "scheme chrome"),
        ("https://", "no host"),
    ],
)
def test_dangerous_urls_are_blocked(url: str, reason_fragment: str) -> None:
    reason = is_blocked_url(url)
    assert reason is not None and reason_fragment in reason


@pytest.mark.parametrize(
    "url",
    [
        "https://appleid-security.com/login",
        "http://paypa1-secure-login.com/",
        "data:image/png;base64,iVBORw0KGgo=",
        "about:blank",
    ],
)
def test_legitimate_capture_targets_are_allowed(url: str) -> None:
    assert is_blocked_url(url) is None


def test_private_blocking_can_be_disabled() -> None:
    assert is_blocked_url("http://127.0.0.1/", block_private_networks=False) is None
    # The scheme rule still applies, whatever the network setting.
    assert is_blocked_url("file:///etc/passwd", block_private_networks=False) is not None


def test_candidate_urls_prefer_https() -> None:
    assert candidate_urls("evil.test") == ["https://evil.test/", "http://evil.test/"]


@pytest.mark.parametrize(
    "host",
    [
        "example.com",
        "sub.example.co.uk",
        "xn--pypal-4ve.com",
        "host-with-dash.io",
        "trailing.dot.",
        "127.0.0.1:8080",  # a port is fine: the host part is still validated
        "example.com:443",
    ],
)
def test_plain_hostnames_are_accepted(host: str) -> None:
    assert is_valid_hostname(host)


@pytest.mark.parametrize(
    "host",
    [
        "evil.com@router.local",  # userinfo: the real host is router.local
        "evil.com@127.0.0.1",
        "evil.com/../x",  # path traversal
        "ev il.com",  # space
        "evil.com#frag",
        "evil.com:notaport",
        "evil.com:8080:9090",
        "évil.com",  # must arrive punycoded
        "",
    ],
)
def test_non_hostname_strings_are_rejected(host: str) -> None:
    assert not is_valid_hostname(host)


@pytest.mark.parametrize(
    ("host", "valid"),
    [("[::1]", True), ("[::1]:8080", True), ("[::1", False), ("[notanip]", False)],
)
def test_ipv6_literals(host: str, valid: bool) -> None:
    assert is_valid_hostname(host) is valid


def test_candidate_urls_follow_the_configured_schemes() -> None:
    assert candidate_urls("evil.test", ["https"]) == ["https://evil.test/"]
    assert candidate_urls("evil.test", ["http", "https"]) == [
        "http://evil.test/",
        "https://evil.test/",
    ]


def test_candidate_urls_reject_unsupported_schemes() -> None:
    with pytest.raises(ValueError, match="unsupported scheme"):
        candidate_urls("evil.test", ["https", "file"])
