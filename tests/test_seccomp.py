"""The capture container's seccomp profile: Docker's default plus Chromium's sandbox (P3.2)."""

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]  # PyYAML ships without type hints

ROOT = Path(__file__).parents[1]
PROFILE = ROOT / "docker" / "capture" / "seccomp-chromium.json"
COMPOSE = ROOT / "docker-compose.yml"
IMAGE = "lookalike-hunter-capture"

# sha256 of moby v27.5.1 profiles/seccomp/default.json, as compact JSON with sorted keys.
DOCKER_DEFAULT_DIGEST = "885442dc08f21f8d60f99ea43d59af88b1c529103815fe24bbf9ce998d3a609d"
SANDBOX_CALLS = ["chroot", "clone", "setns", "unshare"]

# Calls that would let a compromised browser reach the kernel or the host. None of
# them may be allowed without a capability the container does not hold.
NEVER_UNCONDITIONAL = {
    "add_key", "bpf", "finit_module", "init_module", "kexec_load", "keyctl", "mount",
    "open_by_handle_at", "pivot_root", "reboot", "request_key", "swapon", "umount2",
}  # fmt: skip


def profile() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(PROFILE.read_text(encoding="utf-8"))
    return loaded


def digest(document: dict[str, Any]) -> str:
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def test_the_profile_is_dockers_default_plus_one_rule() -> None:
    """Anything else in it would be an unreviewed change to a security boundary."""
    *docker_rules, ours = profile()["syscalls"]

    assert digest({**profile(), "syscalls": docker_rules}) == DOCKER_DEFAULT_DIGEST
    assert ours["names"] == SANDBOX_CALLS and ours["action"] == "SCMP_ACT_ALLOW"
    assert set(ours) == {"names", "action", "comment"}  # no argument or capability tricks


def test_everything_not_listed_is_refused() -> None:
    assert profile()["defaultAction"] == "SCMP_ACT_ERRNO"


def test_no_dangerous_call_is_allowed_without_a_capability() -> None:
    allowed = set()
    for rule in profile()["syscalls"]:
        needs_capability = bool(rule.get("includes", {}).get("caps"))
        if rule["action"] == "SCMP_ACT_ALLOW" and not needs_capability:
            allowed |= set(rule["names"])

    assert allowed & NEVER_UNCONDITIONAL == set()


def test_compose_uses_the_profile_and_never_disables_seccomp() -> None:
    options = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]["capture"][
        "security_opt"
    ]

    assert "seccomp=./docker/capture/seccomp-chromium.json" in options
    assert not any("unconfined" in option for option in options)
    assert "no-new-privileges:true" in options


# ------------------------------------------------------------- in the real container

_LAUNCH = """
import asyncio
from playwright.async_api import async_playwright

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(chromium_sandbox=True)
        page = await browser.new_page()
        await page.goto("data:text/html,<title>sandboxed</title>")
        print(await page.title())
        await browser.close()

asyncio.run(main())
"""


def _image_available() -> bool:
    if shutil.which("docker") is None:
        return False
    found = subprocess.run(
        ["docker", "image", "inspect", IMAGE], capture_output=True, check=False, timeout=60
    )
    return found.returncode == 0


needs_capture_image = pytest.mark.skipif(
    not _image_available(), reason=f"docker or the {IMAGE} image is not available"
)


@needs_capture_image
def test_chromium_starts_sandboxed_in_the_capture_container(tmp_path: Path) -> None:
    """Chromium refuses to start without a working sandbox unless told --no-sandbox.

    Run through compose, so it is the real service definition being tested. Only a
    data: URL is opened: no network call.
    """
    result = subprocess.run(
        ["docker", "compose", "run", "--rm", "--entrypoint", "python", "capture", "-c", _LAUNCH],
        cwd=ROOT,
        env={**os.environ, "LH_CAPTURES_DIR": str(tmp_path)},
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )

    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.strip().endswith("sandboxed")


@needs_capture_image
def test_without_the_extra_rule_the_sandbox_cannot_start() -> None:
    """The control: Docker's default profile on the same locked-down container fails,
    so the one added rule is what the sandbox needs, not something else."""
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--user",
            "pwuser",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--read-only",
            "--tmpfs",
            "/tmp:size=512m,mode=1777",
            "--entrypoint",
            "python",
            IMAGE,
            "-c",
            _LAUNCH,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )

    assert result.returncode != 0
