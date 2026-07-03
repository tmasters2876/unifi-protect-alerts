import httpx
import pytest
import respx

import vision

OPENAI_URL = "https://api.openai.com/v1/chat/completions"


def _completion(content: str) -> dict:
    return {"choices": [{"message": {"content": content}}]}


@pytest.fixture(autouse=True)
def _reset_client():
    vision._client = None
    vision.OPENAI_API_KEY = "test-key"
    yield
    vision._client = None


@respx.mock
async def test_analyze_image_parses_structured_response(multi_subject_vision_json):
    respx.post(OPENAI_URL).mock(
        return_value=httpx.Response(200, json=_completion(multi_subject_vision_json))
    )

    result = await vision.analyze_image(b"fakejpeg")

    assert result.primary_subject_type == "person"
    assert result.weapon_detected is True
    assert len(result.subjects) == 2
    assert {s.type for s in result.subjects} == {"person", "animal"}
    assert "raccoon" in result.notification_message


@respx.mock
async def test_analyze_image_retries_once_on_500_then_succeeds(multi_subject_vision_json):
    route = respx.post(OPENAI_URL).mock(
        side_effect=[
            httpx.Response(500, text="server hiccup"),
            httpx.Response(200, json=_completion(multi_subject_vision_json)),
        ]
    )

    result = await vision.analyze_image(b"fakejpeg")

    assert route.call_count == 2
    assert result.notification_message.startswith("An Asian male")


@respx.mock
async def test_analyze_image_does_not_retry_on_4xx():
    route = respx.post(OPENAI_URL).mock(return_value=httpx.Response(401, json={"error": "bad key"}))

    result = await vision.analyze_image(b"fakejpeg")

    assert route.call_count == 1
    assert result.subjects == []
    assert result.threat_level == "none"
    assert "Vision analysis failed" in result.notification_message


async def test_analyze_image_missing_api_key_returns_sentinel():
    vision.OPENAI_API_KEY = ""
    result = await vision.analyze_image(b"fakejpeg")
    assert result.notification_message == "[OpenAI key missing]"
    assert result.subjects == []


@respx.mock
async def test_analyze_image_malformed_json_returns_sentinel():
    respx.post(OPENAI_URL).mock(
        return_value=httpx.Response(200, json=_completion("not valid json"))
    )
    result = await vision.analyze_image(b"fakejpeg")
    assert result.subjects == []
    assert "unexpected response" in result.notification_message
