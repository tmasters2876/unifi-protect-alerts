import escalation
from vision import Subject, VisionResult


def _vr(**overrides):
    defaults = dict(
        subjects=[],
        notification_message="",
        weapon_detected=False,
        threat_level="none",
        primary_subject_type="none",
    )
    defaults.update(overrides)
    return VisionResult(**defaults)


async def test_weapon_trigger_fires_once_then_debounced(monkeypatch):
    fired = []

    async def fake_fire(url, verify_tls=True):
        fired.append(url)

    monkeypatch.setattr(escalation, "TRIGGER_WEAPON", "https://protect.local/trigger/weapon")
    monkeypatch.setattr(escalation, "TRIGGER_RACCOON", "")
    monkeypatch.setattr(escalation, "fire_protect_trigger", fake_fire)
    escalation._debouncer = escalation.Debouncer()

    vr = _vr(
        subjects=[Subject(type="person", description="armed person", weapon_type="Handgun")],
        weapon_detected=True,
    )
    payload = {"alarm": {"triggers": [{"device": "abcdef0123456789abcdef01"}]}}

    await escalation.maybe_escalate(vr, payload, ts_ms=1735689600000)
    await escalation.maybe_escalate(vr, payload, ts_ms=1735689600000)

    assert fired == ["https://protect.local/trigger/weapon"]  # second call debounced


async def test_no_weapon_trigger_when_not_detected(monkeypatch):
    fired = []

    async def fake_fire(url, verify_tls=True):
        fired.append(url)

    monkeypatch.setattr(escalation, "TRIGGER_WEAPON", "https://protect.local/trigger/weapon")
    monkeypatch.setattr(escalation, "fire_protect_trigger", fake_fire)
    escalation._debouncer = escalation.Debouncer()

    vr = _vr(weapon_detected=False)
    await escalation.maybe_escalate(vr, {}, ts_ms=1735689600000)

    assert fired == []


async def test_raccoon_trigger_only_after_hours(monkeypatch):
    fired = []

    async def fake_fire(url, verify_tls=True):
        fired.append(url)

    monkeypatch.setattr(escalation, "TRIGGER_RACCOON", "https://protect.local/trigger/raccoon")
    monkeypatch.setattr(escalation, "TRIGGER_WEAPON", "")
    monkeypatch.setattr(escalation, "fire_protect_trigger", fake_fire)
    escalation._debouncer = escalation.Debouncer()

    vr = _vr(subjects=[Subject(type="animal", description="a raccoon", species="raccoon")])

    # 2025-01-01 12:00:00 local-ish (daytime) -> should NOT fire
    import time
    daytime_struct = time.struct_time((2025, 1, 1, 12, 0, 0, 0, 0, -1))
    daytime_ts = time.mktime(daytime_struct) * 1000
    await escalation.maybe_escalate(vr, {}, ts_ms=int(daytime_ts))
    assert fired == []

    # 2025-01-01 23:00:00 local-ish (after hours) -> should fire
    night_struct = time.struct_time((2025, 1, 1, 23, 0, 0, 0, 0, -1))
    night_ts = time.mktime(night_struct) * 1000
    await escalation.maybe_escalate(vr, {}, ts_ms=int(night_ts))
    assert fired == ["https://protect.local/trigger/raccoon"]
