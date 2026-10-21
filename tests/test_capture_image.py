"""The capture image and the locked playwright package must be the same release.

Each Playwright release drives only the browser builds its own image ships. Dependabot
bumps the package (uv.lock) and the base image (the Dockerfile) in separate pull
requests, so merging one without the other builds an image whose browser never
starts: every capture then fails. Seen on 2026-10-21 with 1.64 against a 1.63 image.
"""

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def locked_playwright_version() -> str:
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    [version] = [p["version"] for p in lock["package"] if p["name"] == "playwright"]
    return str(version)


def image_playwright_version() -> str:
    dockerfile = (ROOT / "docker" / "capture" / "Dockerfile").read_text(encoding="utf-8")
    match = re.search(r"^FROM mcr\.microsoft\.com/playwright/python:v([\d.]+)-", dockerfile, re.M)
    assert match is not None, "the capture image is no longer built on the Playwright image"
    return match.group(1)


def test_the_capture_image_ships_the_browsers_of_the_locked_playwright() -> None:
    assert image_playwright_version() == locked_playwright_version()
