import pytest

import labeling
from vision import Subject, VisionResult


@pytest.fixture(autouse=True)
def _pin_labeling_flags(monkeypatch):
    # These are read from the real .env at import time; pin them so tests don't
    # depend on the developer's ambient environment.
    monkeypatch.setattr(labeling, "SMART_DETECT_ONLY", False)
    monkeypatch.setattr(labeling, "ANIMAL_SPECIES_FROM_SUMMARY", True)
    monkeypatch.setattr(labeling, "TITLE_ADD_PERSON_GENDER", True)
    monkeypatch.setattr(labeling, "TITLE_ADD_VEHICLE_TYPE", True)
    monkeypatch.setattr(labeling, "TITLE_ADD_VEHICLE_MAKE_MODEL", False)
    monkeypatch.setattr(labeling, "WEAPON_TITLE_HINT", True)


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


def test_primary_kind_prefers_unifi_smart_types_over_ai_guess():
    vr = _vr(primary_subject_type="animal")
    assert labeling.primary_kind({"person"}, vr) == "person"


def test_primary_kind_falls_back_to_ai_guess_when_no_smart_types():
    vr = _vr(primary_subject_type="vehicle")
    assert labeling.primary_kind(set(), vr) == "vehicle"


def test_primary_kind_smart_detect_only_returns_none_without_match(monkeypatch):
    monkeypatch.setattr(labeling, "SMART_DETECT_ONLY", True)
    vr = _vr(primary_subject_type="person")
    assert labeling.primary_kind(set(), vr) == "none"


def test_build_title_single_person_with_weapon():
    vr = _vr(
        subjects=[Subject(type="person", description="a man", apparent_gender="male",
                           weapon_type="Handgun")],
        weapon_detected=True,
    )
    title = labeling.build_title("person", vr, "Front Door")
    assert title == "Person Alert (Handgun) (Male) — Front Door"


def test_build_title_multi_subject_person_and_animal():
    vr = _vr(
        subjects=[
            Subject(type="person", description="a man", apparent_gender="male", weapon_type="AR-type rifle"),
            Subject(type="animal", description="a raccoon", species="raccoon"),
        ],
        weapon_detected=True,
        primary_subject_type="person",
    )
    # UniFi smart types say both person and animal were detected; primary_kind picks person first
    kind = labeling.primary_kind({"person", "animal"}, vr)
    title = labeling.build_title(kind, vr, "Front Door")
    assert title == "Person Alert (AR-type rifle) (Male) — Front Door"


def test_build_title_vehicle_with_type():
    vr = _vr(subjects=[Subject(type="vehicle", description="a truck", vehicle_type="pickup")])
    title = labeling.build_title("vehicle", vr, None)
    assert title == "Vehicle Alert (Pickup)"


def test_build_title_animal_species():
    vr = _vr(subjects=[Subject(type="animal", description="a raccoon", species="raccoon")])
    title = labeling.build_title("animal", vr, "Backyard")
    assert title == "Animal Alert (Raccoon) — Backyard"


def test_build_title_none_kind_is_generic_alert():
    vr = _vr()
    assert labeling.build_title("none", vr, None) == "Alert"


def test_clean_message_strips_leading_alert_prefix():
    assert labeling.clean_message("Alert: something happened") == "something happened"
    assert labeling.clean_message("A person is here") == "A person is here"
