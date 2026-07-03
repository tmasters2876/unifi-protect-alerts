# debug_routes.py — health check + diagnostic endpoints for local/NAS troubleshooting
import os
import time
from typing import Optional

from fastapi import APIRouter, HTTPException, Request

from config import VERIFY_TLS
from labeling import (
    ANIMAL_SPECIES_FROM_SUMMARY,
    SMART_DETECT_ONLY,
    TITLE_ADD_PERSON_GENDER,
    TITLE_ADD_VEHICLE_MAKE_MODEL,
    TITLE_ADD_VEHICLE_TYPE,
    WEAPON_TITLE_HINT,
)
from payload import absolute_url, extract_camera_id_from_urls, find_camera_id, list_image_urls
from unifi import get_camera_map, get_id_name_map, get_snapshot_by_ts, id_to_name
from webhook import _fetch_image_url

router = APIRouter()


@router.get("/health")
async def health():
    return {"ok": True}


@router.get("/debug/env")
async def debug_env():
    return {
        "PROTECT_HOST": os.getenv("PROTECT_HOST"),
        "VERIFY_TLS": os.getenv("VERIFY_TLS"),
        "DEFAULT_CAMERA_ID": os.getenv("DEFAULT_CAMERA_ID"),
        "has_PROTECT_API_KEY": bool(os.getenv("PROTECT_API_KEY")),
        "has_PROTECT_INTEGRATION_KEY": bool(os.getenv("PROTECT_INTEGRATION_KEY")),
        "has_OPENAI_API_KEY": bool(os.getenv("OPENAI_API_KEY")),
        "SMART_DETECT_ONLY": SMART_DETECT_ONLY,
        "ANIMAL_SPECIES_FROM_SUMMARY": ANIMAL_SPECIES_FROM_SUMMARY,
        "TITLE_ADD_PERSON_GENDER": TITLE_ADD_PERSON_GENDER,
        "TITLE_ADD_VEHICLE_TYPE": TITLE_ADD_VEHICLE_TYPE,
        "TITLE_ADD_VEHICLE_MAKE_MODEL": TITLE_ADD_VEHICLE_MAKE_MODEL,
        "WEAPON_TITLE_HINT": WEAPON_TITLE_HINT,
    }


@router.get("/debug/cameramap")
async def debug_cameramap():
    try:
        cmap = await get_camera_map(verify_tls=VERIFY_TLS)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    keys = list(cmap.keys())
    preview = {k: cmap[k] for k in keys[:40]}
    return {"count": len(cmap), "preview_keys": list(preview.keys())}


@router.get("/debug/cameranames")
async def debug_cameranames():
    m = await get_id_name_map(verify_tls=VERIFY_TLS)
    out = {k: m[k] for i, k in enumerate(m.keys()) if i < 20}
    return {"count": len(m), "sample": out}


@router.get("/debug/fetch")
async def debug_fetch(url: str):
    if not url or url.startswith("<PASTE"):
        raise HTTPException(400, "Provide ?url=<actual URL>; got a placeholder.")
    data, ctype, used_auth = await _fetch_image_url(url)
    return {
        "is_image": ctype.startswith("image/"),
        "content_type": ctype,
        "bytes": len(data),
        "auth_used": used_auth,
        "absolute_url": absolute_url(url),
    }


@router.get("/debug/snapshot")
async def debug_snapshot(camera_id: str, ts_ms: Optional[int] = None):
    ts = ts_ms or int(time.time() * 1000)
    try:
        jpeg = await get_snapshot_by_ts(camera_id=camera_id, ts_ms=ts, verify_tls=VERIFY_TLS)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Snapshot fetch failed: {e}")
    return {"ok": True, "bytes": len(jpeg), "ts_ms": ts}


@router.post("/debug/nameprobe")
async def debug_nameprobe(req: Request):
    payload = await req.json()
    urls = list_image_urls(payload)
    cid_payload = find_camera_id(payload)
    cid_from_url = extract_camera_id_from_urls(payload)
    name_from_payload = await id_to_name(cid_payload, verify_tls=VERIFY_TLS)
    name_from_url = await id_to_name(cid_from_url, verify_tls=VERIFY_TLS)
    m = await get_id_name_map(verify_tls=VERIFY_TLS)
    return {
        "image_urls": urls,
        "cid_in_payload": cid_payload,
        "cid_from_url": cid_from_url,
        "name_from_payload": name_from_payload,
        "name_from_url": name_from_url,
        "id_name_map_size": len(m),
    }
