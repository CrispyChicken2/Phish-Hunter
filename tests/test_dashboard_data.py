"""Dashboard data layer, including the escaping the browser depends on."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from lookalike_hunter.capture.models import CaptureResult, CaptureStatus
from lookalike_hunter.classify.schema import Label, Verdict
from lookalike_hunter.dashboard.data import (
    defang,
    label_counts,
    load_findings,
    plain,
)
from lookalike_hunter.ingest.store import MatchStore

NOW = datetime(2026, 9, 28, 10, 0, tzinfo=UTC)


def seed(tmp_path: Path) -> MatchStore:
    store = MatchStore(tmp_path / "t.duckdb", 0.7)
    rows = [
        ("phish.test", Label.PHISHING, 0.95, CaptureStatus.OK),
        ("parked.test", Label.PARKED, 0.80, CaptureStatus.OK),
        ("legit.test", Label.LEGITIMATE, 0.55, CaptureStatus.OK),
    ]
    for index, (fqdn, label, confidence, status) in enumerate(rows, start=1):
        store.save_capture(
            CaptureResult(
                fqdn=fqdn,
                url=f"https://{fqdn}/",
                status=status,
                captured_at=NOW + timedelta(minutes=index),
                duration_ms=100,
                final_url=f"https://{fqdn}/login",
                screenshot_path=Path(f"{fqdn}/shot.png"),
            )
        )
        store.save_verdict(
            capture_id=index,
            fqdn=fqdn,
            backend="mistral",
            model="m",
            verdict=Verdict(label=label, confidence=confidence, evidence=f"{fqdn} evidence"),
            classified_at=NOW + timedelta(minutes=index),
        )
    return store


# ------------------------------------------------------------------- escaping


def test_control_characters_are_removed_and_length_bounded() -> None:
    assert plain("title\x1b[2J", 100) == "title [2J"
    assert len(plain("x" * 5000, 300)) == 300


def test_urls_are_defanged() -> None:
    assert defang("https://evil.test/a") == "hxxps://evil[.]test/a"


def test_the_page_renders_hostile_text_without_markdown_or_html() -> None:
    """st.write and st.caption render Markdown: [x](url) becomes a live link and
    ![](url) makes the analyst's browser call the attacker. Only st.text is safe."""
    import ast

    source = (Path(__file__).parents[1] / "src/lookalike_hunter/dashboard/app.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    render = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "render_finding"
    )
    markdown_calls = [
        node.func.attr
        for node in ast.walk(render)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"write", "caption", "markdown", "header", "subheader"}
    ]
    # One st.markdown, for the badge, guarded by the fixed set of labels.
    assert markdown_calls == ["markdown"]


# ------------------------------------------------------------------- querying


def test_findings_are_newest_first(tmp_path: Path) -> None:
    store = seed(tmp_path)

    findings = load_findings(store.db_path)

    assert [f.fqdn for f in findings] == ["legit.test", "parked.test", "phish.test"]


def test_label_and_confidence_filters(tmp_path: Path) -> None:
    store = seed(tmp_path)

    phishing = load_findings(store.db_path, labels=("phishing",))
    confident = load_findings(store.db_path, min_confidence=0.9)

    assert [f.fqdn for f in phishing] == ["phish.test"]
    assert [f.fqdn for f in confident] == ["phish.test"]


def test_no_filter_returns_every_label(tmp_path: Path) -> None:
    assert len(load_findings(seed(tmp_path).db_path)) == 3


def test_label_counts(tmp_path: Path) -> None:
    assert label_counts(seed(tmp_path).db_path) == {"phishing": 1, "parked": 1, "legitimate": 1}


def test_missing_database_is_empty_not_an_error(tmp_path: Path) -> None:
    assert load_findings(tmp_path / "absent.duckdb") == []
    assert label_counts(tmp_path / "absent.duckdb") == {}


def test_screenshot_path_resolves_against_the_capture_directory(tmp_path: Path) -> None:
    """Captures are written in a container and read from the host."""
    store = seed(tmp_path)
    captures = tmp_path / "captures"
    (captures / "phish.test").mkdir(parents=True)
    (captures / "phish.test" / "shot.png").write_bytes(b"png")

    finding = next(f for f in load_findings(store.db_path) if f.fqdn == "phish.test")

    assert finding.screenshot_file(captures) == (captures / "phish.test" / "shot.png").resolve()


def test_a_screenshot_path_outside_the_capture_directory_is_refused(tmp_path: Path) -> None:
    """The DB is written from the container that runs attacker code."""
    store = MatchStore(tmp_path / "t.duckdb", 0.7)
    (tmp_path / "secret.png").write_bytes(b"png")
    store.save_capture(
        CaptureResult(
            fqdn="evil.test",
            url="https://evil.test/",
            status=CaptureStatus.OK,
            captured_at=NOW,
            duration_ms=1,
            screenshot_path=Path("../secret.png"),
        )
    )
    store.save_verdict(
        capture_id=1,
        fqdn="evil.test",
        backend="mistral",
        model="m",
        verdict=Verdict(label=Label.PHISHING, confidence=0.9, evidence="x"),
        classified_at=NOW,
    )
    captures = tmp_path / "captures"
    captures.mkdir()

    assert load_findings(store.db_path)[0].screenshot_file(captures) is None


def test_a_missing_screenshot_file_is_reported_as_absent(tmp_path: Path) -> None:
    store = seed(tmp_path)
    finding = load_findings(store.db_path)[0]

    assert finding.screenshot_file(tmp_path / "nowhere") is None
