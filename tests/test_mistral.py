import base64
import json
from pathlib import Path

import httpx
import pytest

from lookalike_hunter.capture.signals import PageSignals
from lookalike_hunter.classify.base import ClassificationError, ClassificationInput
from lookalike_hunter.classify.mistral import MistralClassifier, encode_image, list_vision_models
from lookalike_hunter.classify.schema import Label

PNG = bytes.fromhex("89504e470d0a1a0a") + b"fake-png-body"


@pytest.fixture
def screenshot(tmp_path: Path) -> Path:
    path = tmp_path / "shot.png"
    path.write_bytes(PNG)
    return path


def make_item(screenshot: Path) -> ClassificationInput:
    return ClassificationInput(
        fqdn="appleid-security.com",
        suspected_brand="apple",
        screenshot_path=screenshot,
        final_url="https://appleid-security.com/login",
        signals=PageSignals(title="Sign in", form_count=1, has_password_input=True),
    )


def reply(content: str, status: int = 200) -> httpx.Response:
    if status != 200:
        return httpx.Response(status, text=content)
    return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})


def client_returning(
    response: httpx.Response, captured: list[httpx.Request] | None = None
) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if captured is not None:
            captured.append(request)
        return response

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_sends_screenshot_and_signals_then_parses_verdict(screenshot: Path) -> None:
    requests: list[httpx.Request] = []
    verdict_json = json.dumps(
        {
            "label": "phishing",
            "confidence": 0.95,
            "brand_impersonated": "apple",
            "evidence": "Apple ID login form on a domain Apple does not own.",
        }
    )
    classifier = MistralClassifier(
        "key", "pixtral-12b-2409", client=client_returning(reply(verdict_json), requests)
    )

    verdict = await classifier.classify(make_item(screenshot))

    assert verdict.label is Label.PHISHING
    assert verdict.brand_impersonated == "apple"

    body = json.loads(requests[0].content)
    assert requests[0].headers["Authorization"] == "Bearer key"
    assert body["temperature"] == 0
    assert body["response_format"] == {"type": "json_object"}
    parts = body["messages"][1]["content"]
    assert base64.b64encode(PNG).decode() in parts[1]["image_url"]
    assert "appleid-security.com" in parts[0]["text"]


async def test_content_returned_as_parts_is_joined(screenshot: Path) -> None:
    payload = {
        "choices": [
            {
                "message": {
                    "content": [
                        {"type": "text", "text": '{"label": "parked", '},
                        {"type": "text", "text": '"confidence": 0.7, "evidence": "For sale."}'},
                    ]
                }
            }
        ]
    }
    classifier = MistralClassifier(
        "key", "m", client=client_returning(httpx.Response(200, json=payload))
    )
    assert (await classifier.classify(make_item(screenshot))).label is Label.PARKED


@pytest.mark.parametrize(
    ("status", "retryable"),
    [(401, False), (403, False), (400, False), (429, True), (500, True), (503, True)],
)
async def test_http_errors_are_classified_by_retryability(
    screenshot: Path, status: int, retryable: bool
) -> None:
    classifier = MistralClassifier(
        "key", "m", client=client_returning(reply("nope", status=status))
    )
    with pytest.raises(ClassificationError) as excinfo:
        await classifier.classify(make_item(screenshot))
    assert excinfo.value.retryable is retryable


async def test_malformed_model_output_is_retryable(screenshot: Path) -> None:
    classifier = MistralClassifier(
        "key", "m", client=client_returning(reply("I can't help with that."))
    )
    with pytest.raises(ClassificationError) as excinfo:
        await classifier.classify(make_item(screenshot))
    assert excinfo.value.retryable is True


async def test_network_failure_is_retryable(screenshot: Path) -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    classifier = MistralClassifier(
        "key", "m", client=httpx.AsyncClient(transport=httpx.MockTransport(boom))
    )
    with pytest.raises(ClassificationError) as excinfo:
        await classifier.classify(make_item(screenshot))
    assert excinfo.value.retryable is True


def test_oversized_screenshot_is_rejected_without_calling_the_api(tmp_path: Path) -> None:
    big = tmp_path / "big.png"
    big.write_bytes(b"x" * 8_000_001)
    with pytest.raises(ClassificationError) as excinfo:
        encode_image(big)
    assert excinfo.value.retryable is False


async def test_list_vision_models_keeps_only_vision_capable() -> None:
    payload = {
        "data": [
            {"id": "pixtral-12b-2409", "capabilities": {"vision": True}},
            {"id": "mistral-small-latest", "capabilities": {"vision": False}},
            {"id": "mistral-embed"},
        ]
    }
    client = client_returning(httpx.Response(200, json=payload))
    assert await list_vision_models("key", client=client) == ["pixtral-12b-2409"]
