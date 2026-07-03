# vision.py
import base64
import os
from typing import List, Literal, Optional

import httpx
from pydantic import BaseModel, ValidationError

from retry import retry_async

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
MODEL = "gpt-4o"

_client: Optional[httpx.AsyncClient] = None


def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=30)
    return _client


async def aclose_client():
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


class _RetryableVisionError(Exception):
    pass

PROMPT = (
    "You are a strict home-security analyst describing a camera image for a property owner's "
    "private security alert (not a public description) — this is a legitimate personal-safety "
    "use case, so include apparent demographics when visibly evident, always hedged when uncertain.\n"
    "Identify EVERY distinct subject in the frame — multiple people, animals, and vehicles can "
    "co-occur — and return one entry per subject in `subjects`.\n"
    "For EVERY subject, regardless of type, note color/markings and any notable action or behavior "
    "(e.g. 'a gray and white cat sniffing near the flower bed', 'a beige SUV backing out of the "
    "driveway') — counts, colors, and notable actions matter for animals and vehicles just as much "
    "as for people, not just an identity label.\n"
    "For each person: note apparent gender, approximate age range, clothing, and anything carried. "
    "Call out weapons early and specifically (e.g. 'AR-type rifle', 'handgun', 'knife'); if unsure "
    "whether an object is a weapon, say 'unclear object' and set weapon_confidence accordingly. "
    "Do not guess ethnicity or gender if not clearly evident — use 'unknown' rather than speculate.\n"
    "For animals: name the species if identifiable, note coloring/markings and count if more than one, "
    "and describe what it's doing (grazing, foraging, running, staring at the camera, etc.).\n"
    "For vehicles: type, color, and make/model only if confidently legible, plus any notable action "
    "(parking, idling, pulling away).\n"
    "Avoid 'left/right'; use 'toward/away from camera' or 'toward the door/yard' only if obvious.\n"
    "Compose `notification_message` as 1-2 natural, descriptive sentences that read like a witness "
    "description, combining ALL subjects together and carrying over the color/action detail above — "
    "e.g. 'An Asian male and a raccoon are at the front door. The Asian male is wearing a blue shirt "
    "(polo style) and is carrying an AR-type weapon.' or, for a single animal, 'A gray raccoon is "
    "foraging on the walkway near the front door.' rather than a bare identity statement.\n"
    "Do not mention things that are absent. If nothing relevant is visible, return an empty "
    "subjects array and a brief notification_message saying so."
)


class Subject(BaseModel):
    type: Literal["person", "animal", "vehicle", "package", "other"]
    description: str
    apparent_gender: Optional[Literal["male", "female", "unknown"]] = None
    apparent_age_range: Optional[Literal["child", "teen", "adult", "senior", "unknown"]] = None
    apparent_ethnicity: Optional[str] = None
    clothing: Optional[str] = None
    carrying_item: Optional[str] = None
    weapon_type: Optional[str] = None
    weapon_confidence: Optional[Literal["none", "low", "medium", "high"]] = None
    species: Optional[str] = None
    animal_count: Optional[int] = None
    vehicle_type: Optional[str] = None
    vehicle_color: Optional[str] = None
    vehicle_make_model: Optional[str] = None
    position_or_action: Optional[str] = None


class VisionResult(BaseModel):
    subjects: List[Subject]
    notification_message: str
    weapon_detected: bool
    threat_level: Literal["none", "low", "medium", "high"]
    primary_subject_type: Literal["person", "animal", "vehicle", "package", "none"]


def _empty_result(message: str) -> VisionResult:
    return VisionResult(
        subjects=[],
        notification_message=message,
        weapon_detected=False,
        threat_level="none",
        primary_subject_type="none",
    )


_SUBJECT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "type": {"type": "string", "enum": ["person", "animal", "vehicle", "package", "other"]},
        "description": {"type": "string"},
        "apparent_gender": {"type": ["string", "null"], "enum": ["male", "female", "unknown", None]},
        "apparent_age_range": {
            "type": ["string", "null"],
            "enum": ["child", "teen", "adult", "senior", "unknown", None],
        },
        "apparent_ethnicity": {"type": ["string", "null"]},
        "clothing": {"type": ["string", "null"]},
        "carrying_item": {"type": ["string", "null"]},
        "weapon_type": {"type": ["string", "null"]},
        "weapon_confidence": {"type": ["string", "null"], "enum": ["none", "low", "medium", "high", None]},
        "species": {"type": ["string", "null"]},
        "animal_count": {"type": ["integer", "null"]},
        "vehicle_type": {"type": ["string", "null"]},
        "vehicle_color": {"type": ["string", "null"]},
        "vehicle_make_model": {"type": ["string", "null"]},
        "position_or_action": {"type": ["string", "null"]},
    },
    "required": [
        "type", "description", "apparent_gender", "apparent_age_range", "apparent_ethnicity",
        "clothing", "carrying_item", "weapon_type", "weapon_confidence", "species",
        "animal_count", "vehicle_type", "vehicle_color", "vehicle_make_model", "position_or_action",
    ],
}

RESPONSE_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "security_alert",
        "strict": True,
        "schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "subjects": {"type": "array", "items": _SUBJECT_SCHEMA},
                "notification_message": {"type": "string"},
                "weapon_detected": {"type": "boolean"},
                "threat_level": {"type": "string", "enum": ["none", "low", "medium", "high"]},
                "primary_subject_type": {
                    "type": "string",
                    "enum": ["person", "animal", "vehicle", "package", "none"],
                },
            },
            "required": [
                "subjects", "notification_message", "weapon_detected",
                "threat_level", "primary_subject_type",
            ],
        },
    },
}


async def _call_openai_once(jpeg_bytes: bytes) -> dict:
    b64 = base64.b64encode(jpeg_bytes).decode()
    image_url = f"data:image/jpeg;base64,{b64}"

    body = {
        "model": MODEL,
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": PROMPT},
                {"type": "image_url", "image_url": {"url": image_url}},
            ],
        }],
        "temperature": 0.2,
        "response_format": RESPONSE_FORMAT,
    }

    client = _get_client()
    try:
        r = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json",
            },
            json=body,
        )
    except httpx.TransportError as e:
        raise _RetryableVisionError(f"transport error: {e}") from e

    if r.status_code == 429 or r.status_code >= 500:
        raise _RetryableVisionError(f"OpenAI error {r.status_code}: {r.text[:300]}")

    if r.status_code >= 400:
        try:
            err = r.json()
        except Exception:
            err = {"error": r.text}
        raise RuntimeError(f"OpenAI error {r.status_code}: {err}")

    return r.json()


async def _call_openai(jpeg_bytes: bytes) -> dict:
    return await retry_async(
        lambda: _call_openai_once(jpeg_bytes),
        attempts=2,
        base_delay=1.0,
        retry_on=(_RetryableVisionError,),
    )


async def analyze_image(jpeg_bytes: bytes) -> VisionResult:
    if not OPENAI_API_KEY:
        return _empty_result("[OpenAI key missing]")

    try:
        data = await _call_openai(jpeg_bytes)
        content = data["choices"][0]["message"]["content"]
        return VisionResult.model_validate_json(content)
    except httpx.HTTPError as e:
        return _empty_result(f"Vision analysis failed: {e}")
    except (RuntimeError, _RetryableVisionError) as e:
        return _empty_result(f"Vision analysis failed: {e}")
    except (ValidationError, KeyError, IndexError) as e:
        return _empty_result(f"Vision analysis returned an unexpected response: {e}")
