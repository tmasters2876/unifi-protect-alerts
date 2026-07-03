import pytest
from fastapi.testclient import TestClient

import debounce
import escalation
import labeling
import main
import webhook
from vision import VisionResult, Subject

client = TestClient(main.app)


@pytest.fixture(autouse=True)
def _isolate_module_state(monkeypatch):
    # Fresh debouncers per test so runs don't bleed into each other.
    monkeypatch.setattr(webhook, "_notify_debouncer", debounce.Debouncer())
    monkeypatch.setattr(escalation, "_debouncer", debounce.Debouncer())
    monkeypatch.setattr(webhook, "SHARED_SECRET", "")
    # These are read from the real .env at import time; pin them so tests don't
    # depend on the developer's ambient environment.
    monkeypatch.setattr(labeling, "SMART_DETECT_ONLY", False)
    monkeypatch.setattr(labeling, "ANIMAL_SPECIES_FROM_SUMMARY", True)
    monkeypatch.setattr(labeling, "TITLE_ADD_PERSON_GENDER", True)
    monkeypatch.setattr(labeling, "TITLE_ADD_PERSON_ETHNICITY", True)
    monkeypatch.setattr(labeling, "TITLE_ADD_VEHICLE_TYPE", True)
    monkeypatch.setattr(labeling, "TITLE_ADD_VEHICLE_MAKE_MODEL", False)
    monkeypatch.setattr(labeling, "WEAPON_TITLE_HINT", True)
    yield


def test_webhook_rejects_bad_shared_secret(monkeypatch):
    monkeypatch.setattr(webhook, "SHARED_SECRET", "sekrit")
    r = client.post("/unifi-webhook", json={"timestamp": 1735689600000})
    assert r.status_code == 401


def test_webhook_accepts_correct_shared_secret(monkeypatch, data_url_payload):
    monkeypatch.setattr(webhook, "SHARED_SECRET", "sekrit")

    async def fake_analyze_image(img_bytes):
        return VisionResult(
            subjects=[Subject(type="person", description="a person")],
            notification_message="A person is here.",
            weapon_detected=False, threat_level="none", primary_subject_type="person",
        )

    async def fake_send_alert(**kwargs):
        pass

    monkeypatch.setattr(webhook, "analyze_image", fake_analyze_image)
    monkeypatch.setattr(webhook, "send_alert", fake_send_alert)
    monkeypatch.setattr(webhook, "notify_available", lambda: True)

    r = client.post(
        "/unifi-webhook", json=data_url_payload, headers={"x-alert-secret": "sekrit"}
    )
    assert r.status_code == 200


def test_webhook_multi_subject_alert_end_to_end(monkeypatch, data_url_payload, multi_subject_vision_json):
    sent = {}

    async def fake_analyze_image(img_bytes):
        return VisionResult.model_validate_json(multi_subject_vision_json)

    async def fake_send_alert(title, message, image_bytes=None, image_name="alert.jpg"):
        sent["title"] = title
        sent["message"] = message

    monkeypatch.setattr(webhook, "analyze_image", fake_analyze_image)
    monkeypatch.setattr(webhook, "send_alert", fake_send_alert)
    monkeypatch.setattr(webhook, "notify_available", lambda: True)

    r = client.post("/unifi-webhook", json=data_url_payload)

    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert "raccoon" in body["summary"]
    assert sent["title"] == "Person Alert (AR-type rifle) (Asian) (Male) — Front Door"
    assert "Asian male" in sent["message"]
    assert "raccoon" in sent["message"]


def test_webhook_second_event_same_camera_is_debounced(monkeypatch, data_url_payload):
    call_count = {"n": 0}

    async def fake_analyze_image(img_bytes):
        call_count["n"] += 1
        return VisionResult(
            subjects=[], notification_message="ok",
            weapon_detected=False, threat_level="none", primary_subject_type="none",
        )

    async def fake_send_alert(**kwargs):
        pass

    monkeypatch.setattr(webhook, "analyze_image", fake_analyze_image)
    monkeypatch.setattr(webhook, "send_alert", fake_send_alert)
    monkeypatch.setattr(webhook, "notify_available", lambda: True)

    r1 = client.post("/unifi-webhook", json=data_url_payload)
    r2 = client.post("/unifi-webhook", json=data_url_payload)

    assert r1.json().get("debounced") is None
    assert r2.json() == {"ok": True, "debounced": True}
    assert call_count["n"] == 1


def test_webhook_invalid_json_returns_400():
    r = client.post(
        "/unifi-webhook", content=b"not json", headers={"content-type": "application/json"}
    )
    assert r.status_code == 400
