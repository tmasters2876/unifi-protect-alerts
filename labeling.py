# labeling.py — turns a structured VisionResult into an alert title, replacing regex-based inference
import os
from typing import Optional, Set

from vision import Subject, VisionResult

SMART_DETECT_ONLY = os.environ.get("SMART_DETECT_ONLY", "false").strip().lower() in ("1", "true", "yes", "y")
ANIMAL_SPECIES_FROM_SUMMARY = os.environ.get("ANIMAL_SPECIES_FROM_SUMMARY", "true").strip().lower() in ("1", "true", "yes", "y")
TITLE_ADD_PERSON_GENDER = os.environ.get("TITLE_ADD_PERSON_GENDER", "true").strip().lower() in ("1", "true", "yes", "y")
TITLE_ADD_PERSON_ETHNICITY = os.environ.get("TITLE_ADD_PERSON_ETHNICITY", "true").strip().lower() in ("1", "true", "yes", "y")
TITLE_ADD_VEHICLE_TYPE = os.environ.get("TITLE_ADD_VEHICLE_TYPE", "true").strip().lower() in ("1", "true", "yes", "y")
TITLE_ADD_VEHICLE_MAKE_MODEL = os.environ.get("TITLE_ADD_VEHICLE_MAKE_MODEL", "false").strip().lower() in ("1", "true", "yes", "y")
WEAPON_TITLE_HINT = os.environ.get("WEAPON_TITLE_HINT", "true").strip().lower() in ("1", "true", "yes", "y")


def clean_message(message: str) -> str:
    s = (message or "").strip()
    if s.lower().startswith("alert:"):
        s = s.split(":", 1)[1].lstrip()
    return s


def primary_kind(smart_types: Set[str], vr: VisionResult) -> str:
    # UniFi smartDetectTypes still win over AI inference when present (existing documented convention)
    if "person" in smart_types:
        return "person"
    if "vehicle" in smart_types:
        return "vehicle"
    if "package" in smart_types:
        return "package"
    if "animal" in smart_types:
        return "animal"
    if SMART_DETECT_ONLY:
        return "none"
    return vr.primary_subject_type


def _first_subject_of(vr: VisionResult, kind: str) -> Optional[Subject]:
    return next((s for s in vr.subjects if s.type == kind), None)


def build_title(kind: str, vr: VisionResult, camera_name: Optional[str]) -> str:
    title_base = "Alert" if kind == "none" else f"{kind.capitalize()} Alert"

    if WEAPON_TITLE_HINT and vr.weapon_detected:
        weapon_type = next((s.weapon_type for s in vr.subjects if s.weapon_type), None)
        title_base += f" ({weapon_type})" if weapon_type else " (Weapon)"

    if kind == "person":
        person = _first_subject_of(vr, "person")
        if person:
            if TITLE_ADD_PERSON_ETHNICITY and person.apparent_ethnicity and person.apparent_ethnicity.lower() != "unknown":
                title_base += f" ({person.apparent_ethnicity.capitalize()})"
            if TITLE_ADD_PERSON_GENDER and person.apparent_gender and person.apparent_gender != "unknown":
                title_base += f" ({person.apparent_gender.capitalize()})"

    if kind == "animal" and ANIMAL_SPECIES_FROM_SUMMARY:
        animal = _first_subject_of(vr, "animal")
        if animal and animal.species:
            title_base += f" ({animal.species.capitalize()})"

    if kind == "vehicle":
        vehicle = _first_subject_of(vr, "vehicle")
        if vehicle:
            if TITLE_ADD_VEHICLE_MAKE_MODEL and vehicle.vehicle_make_model:
                title_base += f" ({vehicle.vehicle_make_model})"
            elif TITLE_ADD_VEHICLE_TYPE and vehicle.vehicle_type:
                title_base += f" ({vehicle.vehicle_type.capitalize()})"

    if camera_name:
        title_base += f" — {camera_name}"

    return title_base
