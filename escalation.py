# escalation.py — fires Protect Alarm Manager "Trigger Link" URLs based on the vision analysis
import logging
import time
from typing import Any, Dict

from config import DEFAULT_CAMERA_ID, ESCALATION_DEBOUNCE_SEC, TRIGGER_RACCOON, TRIGGER_WEAPON, VERIFY_TLS
from debounce import Debouncer
from payload import extract_camera_id_from_urls, find_camera_id
from unifi import fire_protect_trigger
from vision import VisionResult

LOG = logging.getLogger("uvicorn.error")

_debouncer = Debouncer()


async def maybe_escalate(vr: VisionResult, payload: Dict[str, Any], ts_ms: int):
    """
    Decide if we should fire a Protect inbound trigger based on our analysis.
    Current examples: weapon hint, raccoon after-hours.
    """
    # Camera id to scope debounce per camera
    cam_id = find_camera_id(payload) or extract_camera_id_from_urls(payload) or (DEFAULT_CAMERA_ID or "")
    try:
        # 1) Weapon escalation
        if TRIGGER_WEAPON and vr.weapon_detected and not _debouncer.is_debounced(("weapon", cam_id), ESCALATION_DEBOUNCE_SEC):
            try:
                await fire_protect_trigger(TRIGGER_WEAPON, verify_tls=VERIFY_TLS)
                weapon_type = next((s.weapon_type for s in vr.subjects if s.weapon_type), "weapon")
                LOG.info("[ESCALATE] Fired WEAPON trigger (hint=%s) cam=%s", weapon_type, cam_id or "unknown")
            except Exception as e:
                LOG.warning("[ESCALATE] weapon trigger failed: %s", e)

        # 2) Raccoon after-hours example (customize as you like)
        if TRIGGER_RACCOON:
            is_raccoon = any(
                (s.species or "").lower() == "raccoon" for s in vr.subjects if s.type == "animal"
            )
            # simple after-hours window: 21:00–06:00 local
            loc_hour = time.localtime(ts_ms / 1000).tm_hour
            after_hours = (loc_hour >= 21 or loc_hour < 6)
            if is_raccoon and after_hours and not _debouncer.is_debounced(("raccoon", cam_id), ESCALATION_DEBOUNCE_SEC):
                try:
                    await fire_protect_trigger(TRIGGER_RACCOON, verify_tls=VERIFY_TLS)
                    LOG.info("[ESCALATE] Fired RACCOON trigger (after-hours) cam=%s", cam_id or "unknown")
                except Exception as e:
                    LOG.warning("[ESCALATE] raccoon trigger failed: %s", e)
    except Exception as e:
        LOG.warning("[ESCALATE] unexpected error: %s", e)
