"""What the capture container hands back, and what the host refuses to believe.

Each test is written as the container's attacker would try it: the container
runs hostile pages, and these checks are what stands between it and the
database the host trusts.
"""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from lookalike_hunter.capture.handoff import (
    MAX_RESULTS_BYTES,
    PNG_SIGNATURE,
    CaptureJob,
    ResultWriter,
    import_results,
    job_path,
    new_job,
    read_job,
    results_path,
    write_job,
)
from lookalike_hunter.capture.models import CaptureResult, CaptureStatus
from lookalike_hunter.capture.signals import PageSignals
from lookalike_hunter.config import CaptureConfig

NOW = datetime(2026, 10, 3, 9, 0, tzinfo=UTC)
PNG = PNG_SIGNATURE + b"rest-of-a-png"


def job_for(*targets: str) -> CaptureJob:
    return new_job(list(targets), CaptureConfig(timeout_s=5))


def ok_result(root: Path, fqdn: str = "evil.test") -> CaptureResult:
    (root / fqdn).mkdir(parents=True, exist_ok=True)
    (root / fqdn / "shot.png").write_bytes(PNG)
    return CaptureResult(
        fqdn=fqdn,
        url=f"https://{fqdn}/",
        status=CaptureStatus.OK,
        captured_at=NOW,
        duration_ms=1200,
        final_url=f"https://{fqdn}/login",
        http_status=200,
        screenshot_path=Path(fqdn) / "shot.png",
        html_path=Path(fqdn) / "page.html.txt",
        signals=PageSignals(title="Sign in", form_count=1, has_password_input=True),
    )


def raw_line(root: Path, job: CaptureJob, record: dict[str, object]) -> None:
    path = results_path(root, job.job_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")


def valid_record(fqdn: str = "evil.test") -> dict[str, object]:
    return {
        "fqdn": fqdn,
        "url": f"https://{fqdn}/",
        "status": "timeout",
        "captured_at": NOW.isoformat(),
        "duration_ms": 15000,
    }


# --------------------------------------------------------------------- the job


def test_job_round_trips_through_its_file(tmp_path: Path) -> None:
    job = job_for("a.test", "b.test")
    write_job(job, tmp_path)

    assert read_job(tmp_path, job.job_id) == job


@pytest.mark.parametrize("job_id", ["../../etc/passwd", "a/b", "UPPER", "", "x" * 65])
def test_a_job_id_cannot_name_a_path(tmp_path: Path, job_id: str) -> None:
    with pytest.raises(ValueError):
        job_path(tmp_path, job_id)
    with pytest.raises(ValueError):
        results_path(tmp_path, job_id)


# ------------------------------------------------------------- accepted output


def test_what_the_container_writes_is_imported_intact(tmp_path: Path) -> None:
    job = job_for("evil.test")
    sent = ok_result(tmp_path)
    ResultWriter(tmp_path, job.job_id).write(sent)

    report = import_results(tmp_path, job)

    assert report.rejected == []
    [got] = report.results
    assert got.status is CaptureStatus.OK
    assert got.screenshot_path == Path("evil.test/shot.png")
    assert got.signals == sent.signals
    assert got.captured_at == NOW


def test_no_results_file_means_no_results(tmp_path: Path) -> None:
    report = import_results(tmp_path, job_for("evil.test"))
    assert report.results == [] and report.rejected == []


# ------------------------------------------------------------- refused output


def test_a_hostname_the_job_did_not_ask_for_is_refused(tmp_path: Path) -> None:
    """Otherwise the container could invent captures, and verdicts with them."""
    job = job_for("evil.test")
    raw_line(tmp_path, job, valid_record("paypal.com"))

    report = import_results(tmp_path, job)

    assert report.results == []
    assert "did not ask for" in report.rejected[0]


def test_only_one_result_per_hostname_is_kept(tmp_path: Path) -> None:
    job = job_for("evil.test")
    raw_line(tmp_path, job, valid_record())
    raw_line(tmp_path, job, valid_record())

    report = import_results(tmp_path, job)

    assert len(report.results) == 1 and len(report.rejected) == 1


def test_a_url_unrelated_to_the_hostname_is_refused(tmp_path: Path) -> None:
    job = job_for("evil.test")
    raw_line(tmp_path, job, {**valid_record(), "url": "https://paypal.com/"})

    assert "URL" in import_results(tmp_path, job).rejected[0]


@pytest.mark.parametrize(
    "change",
    [
        {"status": "owned"},
        {"duration_ms": -1},
        {"http_status": 99999},
        {"captured_at": "2026-10-03T09:00:00"},  # no timezone
        {"error": "x" * 5000},
        {"surprise": "extra field"},
        {"signals": {"title": "t", "form_count": "many"}},
    ],
)
def test_malformed_or_oversized_fields_are_refused(
    tmp_path: Path, change: dict[str, object]
) -> None:
    job = job_for("evil.test")
    raw_line(tmp_path, job, {**valid_record(), **change})

    report = import_results(tmp_path, job)

    assert report.results == [] and len(report.rejected) == 1


def test_a_line_that_is_not_json_does_not_stop_the_others(tmp_path: Path) -> None:
    job = job_for("a.test", "b.test")
    raw_line(tmp_path, job, valid_record("a.test"))
    with results_path(tmp_path, job.job_id).open("a", encoding="utf-8") as handle:
        handle.write("{not json\n")
    raw_line(tmp_path, job, valid_record("b.test"))

    report = import_results(tmp_path, job)

    assert [r.fqdn for r in report.results] == ["a.test", "b.test"]
    assert len(report.rejected) == 1


@pytest.mark.parametrize("path", ["../outside.png", "ABSOLUTE", "evil.test/not-a-png.png"])
def test_a_successful_capture_needs_a_real_png_inside_the_directory(
    tmp_path: Path, path: str
) -> None:
    root = tmp_path / "captures"
    root.mkdir()
    (tmp_path / "outside.png").write_bytes(PNG)
    (root / "evil.test").mkdir()
    (root / "evil.test" / "not-a-png.png").write_bytes(b"#!/bin/sh\nrm -rf ~\n")
    stored = str(tmp_path / "outside.png") if path == "ABSOLUTE" else path
    job = job_for("evil.test")
    raw_line(root, job, {**valid_record(), "status": "ok", "screenshot_path": stored})

    report = import_results(root, job)

    assert report.results == []
    assert "screenshot" in report.rejected[0]


def test_a_failed_capture_keeps_no_paths(tmp_path: Path) -> None:
    """A timeout has no screenshot; a path on one would still be read later."""
    job = job_for("evil.test")
    raw_line(tmp_path, job, {**valid_record(), "screenshot_path": "../../.env"})

    [result] = import_results(tmp_path, job).results

    assert result.screenshot_path is None and result.html_path is None


def test_an_oversized_results_file_is_not_read(tmp_path: Path) -> None:
    job = job_for("evil.test")
    path = results_path(tmp_path, job.job_id)
    path.parent.mkdir(parents=True)
    path.write_bytes(b" " * (MAX_RESULTS_BYTES + 1))

    report = import_results(tmp_path, job)

    assert report.results == [] and "larger than" in report.rejected[0]


def test_a_symlinked_results_file_is_not_followed(tmp_path: Path) -> None:
    """A link to ~/.ssh/id_rsa would otherwise be read by the host."""
    root = tmp_path / "captures"
    secret = tmp_path / "secret.jsonl"
    secret.write_text(json.dumps(valid_record()) + "\n", encoding="utf-8")
    job = job_for("evil.test")
    link = results_path(root, job.job_id)
    link.parent.mkdir(parents=True)
    try:
        link.symlink_to(secret)
    except OSError:
        pytest.skip("creating symlinks needs a privilege this machine does not grant")

    report = import_results(root, job)

    assert report.results == [] and "regular file" in report.rejected[0]
