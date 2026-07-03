# webhook.py — POST /unifi-webhook: fetch image, run vision analysis, build alert, notify
import logging
from typing import Any, Dict, Optional, Set

import httpx
from fastapi import APIRouter, HTTPException, Request

from config import BTOKEN, DEFAULT_CAMERA_ID, IKEY, SHARED_SECRET, VERIFY_TLS
from escalation import maybe_escalate
from labeling import build_title, clean_message, primary_kind
from payload import (
    absolute_url,
    data_url_to_bytes,
    extract_camera_id_from_urls,
    extract_smart_types,
    find_camera_id,
    find_timestamp_ms,
    list_image_urls,
    pick_image_source,
)
from unifi import get_id_name_map, get_snapshot_by_ts, resolve_camera_name
from vision import analyze_image
from notify import notify_available, send_alert

LOG = logging.getLogger("uvicorn.error")

router = APIRouter()


async def _fetch_image_url(u: str):
    url = absolute_url(u)
    tried = []
    ctype = ""
    last_content = b""
    async with httpx.AsyncClient(verify=VERIFY_TLS, timeout=20, follow_redirects=True) as cx:
        try:
            r = await cx.get(url); ctype = r.headers.get("content-type","").lower()
            if r.status_code == 200 and ctype.startswith("image/"): return r.content, ctype, "none"
            tried.append(f"none:{r.status_code}:{ctype}"); last_content = r.content
        except Exception as e:
            tried.append(f"none:EXC:{e!r}")
        if IKEY:
            try:
                r = await cx.get(url, headers={"X-API-KEY": IKEY}); ctype = r.headers.get("content-type","").lower()
                if r.status_code == 200 and ctype.startswith("image/"): return r.content, ctype, "x-api-key"
                tried.append(f"x-api-key:{r.status_code}:{ctype}"); last_content = r.content
            except Exception as e:
                tried.append(f"x-api-key:EXC:{e!r}")
        if BTOKEN:
            try:
                r = await cx.get(url, headers={"Authorization": f"Bearer {BTOKEN}"}); ctype = r.headers.get("content-type","").lower()
                if r.status_code == 200 and ctype.startswith("image/"): return r.content, ctype, "bearer"
                tried.append(f"bearer:{r.status_code}:{ctype}"); last_content = r.content
            except Exception as e:
                tried.append(f"bearer:EXC:{e!r}")
    LOG.warning(f"[FETCH_IMAGE] not image or unauthorized; tried={tried} url={url}")
    return last_content, ctype, "failed"


async def _notify(title: str, message: str, image_bytes: bytes | None, image_name: str):
    if not notify_available():
        return
    try:
        if image_bytes:
            try:
                await send_alert(title=title, message=message, image_bytes=image_bytes, image_name=image_name)
            except TypeError:
                await send_alert(title=title, message=message)
        else:
            await send_alert(title=title, message=message)
    except Exception as e:
        LOG.error(f"[NOTIFY] failed: {e}")


async def _process_and_notify(
    img: bytes,
    image_name: str,
    payload: Dict[str, Any],
    smart_types: Set[str],
    ts_ms: int,
    camera_name: Optional[str],
    camera_id: Optional[str] = None,
) -> Dict[str, Any]:
    vr = await analyze_image(img)
    vr.notification_message = clean_message(vr.notification_message)
    kind = primary_kind(smart_types, vr)

    if not camera_name:
        camera_name = await resolve_camera_name(payload, verify_tls=VERIFY_TLS)
    if not camera_name and camera_id and len(camera_id) == 24:
        m = await get_id_name_map(verify_tls=VERIFY_TLS)
        camera_name = m.get(camera_id)

    title = build_title(kind, vr, camera_name)
    await maybe_escalate(vr, payload, ts_ms)
    await _notify(title=title, message=vr.notification_message, image_bytes=img, image_name=image_name)
    return {
        "ok": True,
        "summary": vr.notification_message,
        "camera": camera_name or camera_id or "unknown",
        "ts_ms": ts_ms,
    }


@router.post("/unifi-webhook")
async def unifi_webhook(req: Request):
    LOG.info("[WEBHOOK] hit /unifi-webhook")

    if SHARED_SECRET:
        given = (
            req.headers.get("x-alert-secret")
            or req.headers.get("x-shared-secret")
            or req.headers.get("x-webhook-secret")
            or req.headers.get("x-webhook-token")
            or req.query_params.get("secret")
        )
        if given != SHARED_SECRET:
            LOG.warning("[WEBHOOK] forbidden: shared secret mismatch/missing")
            raise HTTPException(status_code=401, detail="Unauthorized (bad secret)")

    try:
        payload = await req.json()
    except Exception:
        raw = (await req.body())[:300]
        LOG.error(f"[WEBHOOK] invalid JSON. First bytes: {raw!r}")
        raise HTTPException(status_code=400, detail="Invalid JSON")

    LOG.info(f"[WEBHOOK] top-level keys: {list(payload.keys())}")

    ts_ms = find_timestamp_ms(payload)

    # *** EARLY camera name resolution (works for both data and url flows) ***
    camera_name = await resolve_camera_name(payload, verify_tls=VERIFY_TLS)
    if not camera_name:
        urls = list_image_urls(payload)
        cid_guess = extract_camera_id_from_urls(payload)
        LOG.info(f"[NAME] urls={urls[:3]} extracted_cid={cid_guess!r}")

    smart_types = extract_smart_types(payload)
    LOG.info(f"[SMART] uni_smart_types={sorted(list(smart_types))}")

    # 1) Thumbnail/data-image first
    src_kind, src_val = pick_image_source(payload)
    if src_kind == "data":
        img = data_url_to_bytes(src_val)
        if img:
            return await _process_and_notify(img, "thumb.jpg", payload, smart_types, ts_ms, camera_name)
        else:
            LOG.warning("[WEBHOOK] data:image present but could not decode; falling back")

    if src_kind == "url":
        img, ctype, how = await _fetch_image_url(src_val)
        if ctype.startswith("image/") and img:
            LOG.info(f"[WEBHOOK] using thumbnail ({ctype}, auth={how}, bytes={len(img)})")
            return await _process_and_notify(img, "thumb.jpg", payload, smart_types, ts_ms, camera_name)
        else:
            LOG.warning(f"[WEBHOOK] thumbnail not usable (ctype={ctype}); will try snapshot")

    # 2) Snapshot fallback
    camera_id = find_camera_id(payload) or DEFAULT_CAMERA_ID
    if not camera_id:
        LOG.error("[WEBHOOK] no camera id found in payload and no DEFAULT_CAMERA_ID set")
        raise HTTPException(status_code=400, detail="No camera id found in webhook payload")

    jpeg = await get_snapshot_by_ts(camera_id=camera_id, ts_ms=ts_ms, verify_tls=VERIFY_TLS)
    return await _process_and_notify(
        jpeg, "snapshot.jpg", payload, smart_types, ts_ms, camera_name, camera_id=camera_id
    )
