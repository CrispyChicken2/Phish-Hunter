"""Mistral vision backend (Pixtral and other multimodal models).

One API key gives access to every model on the account; the model is chosen per
request by name, so :func:`list_vision_models` reports what is actually callable.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

import httpx

from lookalike_hunter.classify.base import ClassificationError, ClassificationInput
from lookalike_hunter.classify.schema import (
    SYSTEM_PROMPT,
    Verdict,
    build_user_prompt,
    parse_verdict,
)
from lookalike_hunter.logging import get_logger

log = get_logger(__name__)

# Screenshots are the whole point of the capture, but a full-page shot of a long
# site is megabytes; Mistral rejects oversized payloads.
MAX_IMAGE_BYTES = 8_000_000


def encode_image(path: Path) -> str:
    data = path.read_bytes()
    if len(data) > MAX_IMAGE_BYTES:
        raise ClassificationError(f"screenshot too large: {len(data)} bytes", retryable=False)
    return "data:image/png;base64," + base64.b64encode(data).decode("ascii")


class MistralClassifier:
    """Calls the chat completions endpoint with a screenshot and the page signals."""

    name = "mistral"

    def __init__(
        self,
        api_key: str,
        model: str,
        api_base: str = "https://api.mistral.ai/v1",
        timeout_s: float = 90.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.model = model
        self.api_base = api_base.rstrip("/")
        self._timeout = timeout_s
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=timeout_s)
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    def _payload(self, item: ClassificationInput) -> dict[str, Any]:
        user_text = build_user_prompt(item.fqdn, item.suspected_brand, item.final_url, item.signals)
        return {
            "model": self.model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": user_text},
                        {
                            "type": "image_url",
                            "image_url": encode_image(item.screenshot_path),
                        },
                    ],
                },
            ],
        }

    async def classify(self, item: ClassificationInput) -> Verdict:
        try:
            response = await self._client.post(
                f"{self.api_base}/chat/completions",
                headers=self._headers,
                json=self._payload(item),
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:
            raise ClassificationError(f"request failed: {exc}") from exc

        self._raise_for_status(response)
        try:
            content = response.json()["choices"][0]["message"]["content"]
        except (KeyError, IndexError, ValueError) as exc:
            raise ClassificationError(f"unexpected API response shape: {exc}") from exc
        if isinstance(content, list):  # some models return content parts
            content = "".join(part.get("text", "") for part in content)
        try:
            return parse_verdict(content)
        except ValueError as exc:
            # Retryable: the model ignored the JSON contract this time.
            raise ClassificationError(str(exc)) from exc

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        if response.is_success:
            return
        body = response.text[:300]
        # Auth and request-shape problems will not fix themselves on a retry;
        # rate limits and server errors will.
        retryable = response.status_code == 429 or response.status_code >= 500
        raise ClassificationError(
            f"API returned {response.status_code}: {body}", retryable=retryable
        )


async def list_vision_models(
    api_key: str,
    api_base: str = "https://api.mistral.ai/v1",
    client: httpx.AsyncClient | None = None,
) -> list[str]:
    """Model ids on this account that accept images, sorted by id."""
    owned = client is None
    client = client or httpx.AsyncClient(timeout=30)
    try:
        response = await client.get(
            f"{api_base.rstrip('/')}/models",
            headers={"Authorization": f"Bearer {api_key}"},
        )
    finally:
        if owned:
            await client.aclose()
    if not response.is_success:
        raise ClassificationError(
            f"listing models failed: {response.status_code} {response.text[:200]}",
            retryable=False,
        )
    models: list[str] = []
    for entry in response.json().get("data", []):
        capabilities = entry.get("capabilities") or {}
        if capabilities.get("vision"):
            models.append(str(entry.get("id")))
    return sorted(models)
