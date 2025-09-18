# main.py
import os, base64
import httpx
import logging
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")

from typing import Any, Dict, Optional, Tuple, Iterable

from fastapi import FastAPI, UploadFile, File, Request, HTTPException
from pydantic import BaseModel

from unifi import get_snapshot_by_ts, UnifiAuthError, get_camera_map
from vision import analyze_image
from notify import send_alert, notify_available

VERIFY_TLS = os.environ.get("VERIFY_TLS", "true").lower() == "true"
SHARED_SECRET = os.environ.get("ALERT_SHARED_SECRET", "")
DEFAULT_CAMERA_ID = os.environ.get("DEFAULT_CAMERA_ID")
PROTECT_HOST = (os.environ.get("PROTECT_HOST") or "").rstrip("/")
IKEY = os.environ.get("PROTECT_INTEGRATION_KEY") or ""
BTOKEN = os.environ.get("PROTECT_API_KEY") or ""
LOG = logging.getLogger("uvicorn.error")

app = FastAPI(title="UniFi AI Alerts")

class ProtectAlarm(BaseModel):
    alarm: Dict[str, Any]
    timestamp: int

# -------------------- Debug routes --------------------

@app.get("/health")
async def health():
    return {"ok": True}

@app.get("/debug/env")
async def debug_env():
    return {
        "PROTECT_HOST": os.getenv("PROTECT_HOST"),
        "VERIFY_TLS": os.getenv("VERIFY_TLS"),
        "DEFAULT_CAMERA_ID": os.getenv("DEFAULT_CAMERA_ID"),
        "has_PROTECT_API_KEY": bool(os.getenv("PROTECT_API_KEY")),
        "has_PROTECT_INTEGRATION_KEY": bool(os.getenv("PROTECT_INTEGRATION_KEY")),
        "has_OPENAI_API_KEY": bool(os.getenv("OPENAI_API_KEY")),
    }

@app.get("/debug/cameramap")
async def debug_cameramap():
    try:
        cmap = await get_camera_map(verify_tls=VERIFY_TLS)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    keys = list(cmap.keys())
    preview = {k: cmap[k] for k in keys[:40]}
    return {"count": len(cmap), "preview_keys": list(preview.keys())}

@app.get("/debug/fetch")
async def debug_fetch(url: str):
    if not url or url.startswith("<PASTE"):
        raise HTTPException(400, "Provide ?url=<actual URL>; got a placeholder.")
    data, ctype, used_auth = await _fetch_image_url(url)
    return {
        "is_image": ctype.startswith("image/"),
        "content_type": ctype,
        "bytes": len(data),
        "auth_used": used_auth,
        "absolute_url": _absolute_url(url),
    }

@app.post("/debug/extract")
async def debug_extract(req: Request):
    """POST raw webhook JSON here to see what image we would use."""
    payload = await req.json()
    src_kind, src_value = _pick_image_source(payload)
    if not src_kind:
        return {"found": False}
    if src_kind == "data":
        b = _data_url_to_bytes(src_value)
        return {"found": True, "kind": "data", "bytes": len(b)}
    else:
        data, ctype, how = await _fetch_image_url(src_value)
        return {
            "found": True,
            "kind": "url",
            "content_type": ctype,
            "bytes": len(data),
            "auth_used": how,
            "url": _absolute_url(src_value),
            "is_image": ctype.startswith("image/"),
        }

@app.get("/debug/snapshot")
async def debug_snapshot(camera_id: str, ts_ms: Optional[int] = None):
    import time
    ts = ts_ms or int(time.time() * 1000)
    try:
        jpeg = await get_snapshot_by_ts(camera_id=camera_id, ts_ms=ts, verify_tls=VERIFY_TLS)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Snapshot fetch failed: {e}")
    return {"ok": True, "bytes": len(jpeg), "ts_ms": ts}

# -------------------- Helpers --------------------

def _first_nonempty(*vals) -> Optional[Any]:
    for v in vals:
        if v is not None and v != "":
            return v
    return None

def _find_camera_id(payload: Dict[str, Any]) -> Optional[str]:
    alarm = payload.get("alarm")
    if isinstance(alarm, dict):
        triggers = alarm.get("triggers") or []
        if isinstance(triggers, list):
            for t in triggers:
                if isinstance(t, dict):
                    cid = _first_nonempty(
                        t.get("device"), t.get("camera"), t.get("cameraId"), t.get("deviceId")
                    )
                    if cid:
                        return str(cid)
    flat = ["cameraId","camera_id","camera","device","deviceId","device_id","sourceCamera","source"]
    for k in flat:
        if k in payload and payload[k]:
            return str(payload[k])
    for k in ["event","trigger","device","camera","resource"]:
        obj = payload.get(k)
        if isinstance(obj, dict):
            cid = _first_nonempty(obj.get("cameraId"), obj.get("camera_id"), obj.get("deviceId"), obj.get("device"))
            if cid:
                return str(cid)
    return None

def _find_timestamp_ms(payload: Dict[str, Any]) -> int:
    import time, datetime as dt
    for k in ["timestamp","ts","timeMs","time_ms"]:
        v = payload.get(k)
        if isinstance(v, (int, float)) and v > 1_000_000_000:
            return int(v)
    for parent in ["event","alarm","trigger"]:
        obj = payload.get(parent)
        if isinstance(obj, dict):
            for k in ["timestamp","ts","triggeredAt","when","start","startTime"]:
                v = obj.get(k)
                if isinstance(v, (int, float)) and v > 1_000_000_000:
                    return int(v)
                if isinstance(v, str):
                    try:
                        iso = v.replace("Z","+00:00")
                        return int(dt.datetime.fromisoformat(iso).timestamp() * 1000)
                    except Exception:
                        pass
    return int(time.time() * 1000)

def _absolute_url(u: str) -> str:
    if not isinstance(u, str) or not u:
        return ""
    if u.startswith("http://") or u.startswith("https://"):
        return u
    if u.startswith("/"):
        return f"{PROTECT_HOST}{u}"
    return u  # unknown form; let caller handle

def _data_url_to_bytes(s: str) -> bytes:
    # e.g., data:image/jpeg;base64,/9j/4AAQSk...
    try:
        head, b64 = s.split(",", 1)
        return base64.b64decode(b64)
    except Exception:
        return b""

def _iter_image_candidates(payload: Any) -> Iterable[Tuple[str, str]]:
    """
    Yield (kind, value):
      - ("data", "data:image/jpeg;base64,...")
      - ("url",  "http(s)://...") or ("url", "/proxy/...")
    We look for keys containing common terms and we also accept direct string values.
    """
    QUEUE = [payload]
    while QUEUE:
        node = QUEUE.pop(0)
        if isinstance(node, dict):
            for k, v in node.items():
                lk = k.lower()
                if isinstance(v, str):
                    vs = v.strip()
                    if vs.startswith("data:image/"):
                        yield ("data", vs)
                    elif vs.startswith("http://") or vs.startswith("https://") or vs.startswith("/"):
                        if any(t in lk for t in ("image", "thumb", "thumbnail", "snapshot", "preview", "still")):
                            yield ("url", vs)
                elif isinstance(v, (dict, list)):
                    QUEUE.append(v)
        elif isinstance(node, list):
            for v in node:
                if isinstance(v, (dict, list)):
                    QUEUE.append(v)
                elif isinstance(v, str):
                    vs = v.strip()
                    if vs.startswith("data:image/"):
                        yield ("data", vs)
                    elif vs.startswith("http://") or vs.startswith("https://") or vs.startswith("/"):
                        yield ("url", vs)

def _pick_image_source(payload: Any) -> Tuple[Optional[str], Optional[str]]:
    """
    Return the first viable thumbnail candidate, preferring:
      1) data:image/*  (already bytes)
      2) http(s) URLs
      3) relative URLs (start with '/')
    """
    url_rel = None
    for kind, val in _iter_image_candidates(payload):
        if kind == "data":
            return ("data", val)
        if kind == "url":
            if val.startswith("http"):
                return ("url", val)
            if not url_rel:
                url_rel = val
    if url_rel:
        return ("url", url_rel)
    return (None, None)

async def _fetch_image_url(u: str):
    """
    Try to GET a thumbnail/image URL using: no auth → Integration key → Bearer.
    Returns (bytes, content_type, which_auth_used_string)
    """
    url = _absolute_url(u)
    tried = []
    ctype = ""
    last_content = b""

    async with httpx.AsyncClient(verify=VERIFY_TLS, timeout=20, follow_redirects=True) as cx:
        # 1) no auth
        try:
            r = await cx.get(url)
            ctype = r.headers.get("content-type","").lower()
            if r.status_code == 200 and ctype.startswith("image/"):
                return r.content, ctype, "none"
            tried.append(f"none:{r.status_code}:{ctype}")
            last_content = r.content
        except Exception as e:
            tried.append(f"none:EXC:{e!r}")

        # 2) Integration key
        if IKEY:
            try:
                r = await cx.get(url, headers={"X-API-KEY": IKEY})
                ctype = r.headers.get("content-type","").lower()
                if r.status_code == 200 and ctype.startswith("image/"):
                    return r.content, ctype, "x-api-key"
                tried.append(f"x-api-key:{r.status_code}:{ctype}")
                last_content = r.content
            except Exception as e:
                tried.append(f"x-api-key:EXC:{e!r}")

        # 3) Bearer token (if provided)
        if BTOKEN:
            try:
                r = await cx.get(url, headers={"Authorization": f"Bearer {BTOKEN}"})
                ctype = r.headers.get("content-type","").lower()
                if r.status_code == 200 and ctype.startswith("image/"):
                    return r.content, ctype, "bearer"
                tried.append(f"bearer:{r.status_code}:{ctype}")
                last_content = r.content
            except Exception as e:
                tried.append(f"bearer:EXC:{e!r}")

    LOG.warning(f"[FETCH_IMAGE] not image or unauthorized; tried={tried} url={url}")
    return last_content, ctype, "failed"

async def _notify(title: str, message: str, image_bytes: bytes | None, image_name: str):
    """Send pushover; compatible with old/new notify.py (with/without image support)."""
    if not notify_available():
        return
    try:
        if image_bytes:
            try:
                # New notify.py with attachment support
                await send_alert(title=title, message=message, image_bytes=image_bytes, image_name=image_name)
            except TypeError:
                # Old notify.py (no image params)
                await send_alert(title=title, message=message)
        else:
            await send_alert(title=title, message=message)
    except Exception as e:
        LOG.error(f"[NOTIFY] failed: {e}")

# -------------------- Webhook --------------------

@app.post("/unifi-webhook")
async def unifi_webhook(req: Request):
    LOG.info("[WEBHOOK] hit /unifi-webhook")

    if SHARED_SECRET:
        given = req.headers.get("x-alert-secret")
        if given != SHARED_SECRET:
            LOG.warning("[WEBHOOK] bad secret header")
            raise HTTPException(status_code=401, detail="Unauthorized (bad secret)")

    try:
        payload = await req.json()
    except Exception:
        raw = (await req.body())[:300]
        LOG.error(f"[WEBHOOK] invalid JSON. First bytes: {raw!r}")
        raise HTTPException(status_code=400, detail="Invalid JSON")

    LOG.info(f"[WEBHOOK] top-level keys: {list(payload.keys())}")

    ts_ms = _find_timestamp_ms(payload)
    name = (payload.get("alarm") or {}).get("name") or payload.get("name") or "Protect Alarm"

    # 1) Thumbnail/data-image first (works across all cameras; no cameraId mapping needed)
    src_kind, src_val = _pick_image_source(payload)
    if src_kind == "data":
        img = _data_url_to_bytes(src_val)
        if img:
            try:
                summary = await analyze_image(img)
            except Exception as e:
                LOG.error(f"[WEBHOOK] vision(thumbnail-data) failed: {e}")
                raise HTTPException(status_code=400, detail=str(e))
            await _notify(title=name, message=summary, image_bytes=img, image_name="thumb.jpg")
            return {"ok": True, "summary": summary, "camera_id": "thumbnail-data", "ts_ms": ts_ms}
        else:
            LOG.warning("[WEBHOOK] data:image thumbnail present but could not decode; falling back")

    if src_kind == "url":
        img, ctype, how = await _fetch_image_url(src_val)
        if ctype.startswith("image/") and img:
            LOG.info(f"[WEBHOOK] using thumbnail ({ctype}, auth={how}, bytes={len(img)})")
            try:
                summary = await analyze_image(img)
            except Exception as e:
                LOG.error(f"[WEBHOOK] vision(thumbnail-url) failed: {e}")
                raise HTTPException(status_code=400, detail=str(e))
            await _notify(title=name, message=summary, image_bytes=img, image_name="thumb.jpg")
            return {"ok": True, "summary": summary, "camera_id": "thumbnail-url", "ts_ms": ts_ms}
        else:
            LOG.warning(f"[WEBHOOK] thumbnail not usable (ctype={ctype}); will try snapshot")

    # 2) Snapshot fallback (requires integration id; MACs cannot be resolved on your firmware)
    camera_id = _find_camera_id(payload) or DEFAULT_CAMERA_ID
    if not camera_id:
        LOG.error("[WEBHOOK] no camera id found in payload and no DEFAULT_CAMERA_ID set")
        raise HTTPException(status_code=400, detail="No camera id found in webhook payload")

    try:
        jpeg = await get_snapshot_by_ts(camera_id=camera_id, ts_ms=ts_ms, verify_tls=VERIFY_TLS)
    except Exception as e:
        LOG.error(f"[WEBHOOK] snapshot fetch failed: {e}")
        raise HTTPException(status_code=400, detail=f"Snapshot fetch failed: {e}")

    try:
        summary = await analyze_image(jpeg)
    except Exception as e:
        LOG.error(f"[WEBHOOK] vision failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))

    await _notify(title=name, message=summary, image_bytes=jpeg, image_name="snapshot.jpg")
    return {"ok": True, "summary": summary, "camera_id": camera_id, "ts_ms": ts_ms}
