# main.py
import os, base64, time, asyncio
import httpx
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")

from typing import Any, Dict, Optional, Tuple, Iterable, Set

from fastapi import FastAPI, UploadFile, File, Request, HTTPException
from pydantic import BaseModel

# URL + regex helpers (for cameraId extraction from thumbnail URLs)
import urllib.parse as _urlparse
from urllib.parse import urlparse, parse_qs
import re as _re

from unifi import get_snapshot_by_ts, UnifiAuthError, get_camera_map, fire_protect_trigger
from vision import analyze_image, VisionResult
from notify import send_alert, notify_available
from labeling import (
    primary_kind,
    build_title,
    clean_message,
    SMART_DETECT_ONLY,
    ANIMAL_SPECIES_FROM_SUMMARY,
    TITLE_ADD_PERSON_GENDER,
    TITLE_ADD_VEHICLE_TYPE,
    TITLE_ADD_VEHICLE_MAKE_MODEL,
    WEAPON_TITLE_HINT,
)

VERIFY_TLS = os.environ.get("VERIFY_TLS", "true").lower() == "true"
SHARED_SECRET = os.environ.get("ALERT_SHARED_SECRET", "")
DEFAULT_CAMERA_ID = os.environ.get("DEFAULT_CAMERA_ID")
PROTECT_HOST = (os.environ.get("PROTECT_HOST") or "").rstrip("/")
IKEY = os.environ.get("PROTECT_INTEGRATION_KEY") or ""
BTOKEN = os.environ.get("PROTECT_API_KEY") or ""  # optional; not required here
LOG = logging.getLogger("uvicorn.error")

# Persist logs to disk (docker-compose mounts ./logs on the NAS) in addition to stdout.
_LOG_DIR = Path(__file__).resolve().parent / "logs"
try:
    _LOG_DIR.mkdir(exist_ok=True)
    _file_handler = RotatingFileHandler(_LOG_DIR / "app.log", maxBytes=5_000_000, backupCount=3)
    _file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    LOG.addHandler(_file_handler)
except OSError as e:
    LOG.warning(f"[LOGGING] could not set up file logging: {e}")

# Behavior flags (label/title flags now live in labeling.py, single source of truth)
TRIGGER_WEAPON   = os.environ.get("PROTECT_TRIGGER_WEAPON", "")
TRIGGER_RACCOON  = os.environ.get("PROTECT_TRIGGER_RACCOON", "")
ESCALATION_DEBOUNCE_SEC = int(os.environ.get("ESCALATION_DEBOUNCE_SEC", "60"))

_ESC_LAST: dict[tuple, float] = {}
def _debounced(key: tuple, window: int = ESCALATION_DEBOUNCE_SEC) -> bool:
    now = time.time()
    last = _ESC_LAST.get(key, 0.0)
    if now - last < window:
        return True
    _ESC_LAST[key] = now
    return False


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
        "SMART_DETECT_ONLY": SMART_DETECT_ONLY,
        "ANIMAL_SPECIES_FROM_SUMMARY": ANIMAL_SPECIES_FROM_SUMMARY,
        "TITLE_ADD_PERSON_GENDER": TITLE_ADD_PERSON_GENDER,
        "TITLE_ADD_VEHICLE_TYPE": TITLE_ADD_VEHICLE_TYPE,
        "TITLE_ADD_VEHICLE_MAKE_MODEL": TITLE_ADD_VEHICLE_MAKE_MODEL,
        "WEAPON_TITLE_HINT": WEAPON_TITLE_HINT,
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

@app.get("/debug/cameranames")
async def debug_cameranames():
    m = await _get_id_name_map()
    out = {k: m[k] for i, k in enumerate(m.keys()) if i < 20}
    return {"count": len(m), "sample": out}

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

@app.get("/debug/snapshot")
async def debug_snapshot(camera_id: str, ts_ms: Optional[int] = None):
    ts = ts_ms or int(time.time() * 1000)
    try:
        jpeg = await get_snapshot_by_ts(camera_id=camera_id, ts_ms=ts, verify_tls=VERIFY_TLS)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Snapshot fetch failed: {e}")
    return {"ok": True, "bytes": len(jpeg), "ts_ms": ts}

@app.post("/debug/nameprobe")
async def debug_nameprobe(req: Request):
    payload = await req.json()
    urls = _list_image_urls(payload)
    cid_payload = _find_camera_id(payload)
    cid_from_url = _extract_camera_id_from_urls(payload)
    name_from_payload = await _id_to_name(cid_payload)
    name_from_url = await _id_to_name(cid_from_url)
    m = await _get_id_name_map()
    return {
        "image_urls": urls,
        "cid_in_payload": cid_payload,
        "cid_from_url": cid_from_url,
        "name_from_payload": name_from_payload,
        "name_from_url": name_from_url,
        "id_name_map_size": len(m),
    }

# -------------------- Helpers --------------------

# Extract a 24-hex camera id from any thumbnail/snapshot URL
_HEX24 = _re.compile(r'(?i)[0-9a-f]{24}')

def _list_image_urls(payload: Any):
    urls = []
    for kind, val in _iter_image_candidates(payload):
        if kind == "url":
            urls.append(_absolute_url(val))
    return urls

def _extract_camera_id_from_urls(payload: Any) -> Optional[str]:
    for kind, val in _iter_image_candidates(payload):
        if kind != "url":
            continue
        u = _absolute_url(val)
        parsed = urlparse(u)
        qs = parse_qs(parsed.query)
        for key in ("cameraId", "camera", "id", "entityId"):
            vlist = qs.get(key) or qs.get(key.lower())
            if vlist:
                for v in vlist:
                    if isinstance(v, str) and _HEX24.fullmatch(v):
                        return v
        for seg in parsed.path.split("/"):
            if _HEX24.fullmatch(seg):
                return seg
        m = _HEX24.search(_urlparse.unquote(u))
        if m:
            return m.group(0)
    return None

async def _id_to_name(cid: Optional[str]) -> Optional[str]:
    if isinstance(cid, str) and len(cid) == 24:
        m = await _get_id_name_map()
        return m.get(cid)
    return None

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

def _find_camera_name_in_payload(payload: Dict[str, Any]) -> Optional[str]:
    for k in ("cameraName","camera_name","deviceName","device_name","sourceName","source_name"):
        v = payload.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    alarm = payload.get("alarm")
    if isinstance(alarm, dict):
        for k in ("cameraName","camera_name","deviceName","device_name"):
            v = alarm.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
        triggers = alarm.get("triggers") or []
        if isinstance(triggers, list):
            for t in triggers:
                if isinstance(t, dict):
                    for k in ("cameraName","deviceName"):
                        v = t.get(k)
                        if isinstance(v, str) and v.strip():
                            return v.strip()
    cam = payload.get("camera")
    if isinstance(cam, dict):
        for k in ("name","cameraName","deviceName"):
            v = cam.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return None

def _find_timestamp_ms(payload: Dict[str, Any]) -> int:
    import datetime as dt
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
    return u

def _data_url_to_bytes(s: str) -> bytes:
    try:
        _, b64 = s.split(",", 1)
        return base64.b64decode(b64)
    except Exception:
        return b""

def _iter_image_candidates(payload: Any) -> Iterable[Tuple[str, str]]:
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
                        if any(t in lk for t in ("image","thumb","thumbnail","snapshot","preview","still")):
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

def _extract_smart_types(payload: Dict[str, Any]) -> Set[str]:
    types: Set[str] = set()
    def collect(obj: Any):
        if not isinstance(obj, dict): return
        for k in ("smartDetectTypes","smartDetect","smartDetections"):
            v = obj.get(k)
            if isinstance(v, list):
                for t in v:
                    if isinstance(t, str):
                        types.add(t.lower())
    collect(payload)
    for p in ("alarm","event","trigger"):
        o = payload.get(p)
        if isinstance(o, dict):
            collect(o)
    return types

async def _maybe_escalate(vr: VisionResult, payload: Dict[str, Any], ts_ms: int):
    """
    Decide if we should fire a Protect inbound trigger based on our analysis.
    Current examples: weapon hint, raccoon after-hours.
    """
    # Camera id to scope debounce per camera
    cam_id = _find_camera_id(payload) or _extract_camera_id_from_urls(payload) or (DEFAULT_CAMERA_ID or "")
    try:
        # 1) Weapon escalation
        if TRIGGER_WEAPON and vr.weapon_detected and not _debounced(("weapon", cam_id)):
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
            if is_raccoon and after_hours and not _debounced(("raccoon", cam_id)):
                try:
                    await fire_protect_trigger(TRIGGER_RACCOON, verify_tls=VERIFY_TLS)
                    LOG.info("[ESCALATE] Fired RACCOON trigger (after-hours) cam=%s", cam_id or "unknown")
                except Exception as e:
                    LOG.warning("[ESCALATE] raccoon trigger failed: %s", e)
    except Exception as e:
        LOG.warning("[ESCALATE] unexpected error: %s", e)


# -------------------- Networking / notify --------------------

async def _fetch_image_url(u: str):
    url = _absolute_url(u)
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

# ---------- ID → Name cache (Integration API) ----------
_ID_NAME_CACHE = {"ts": 0.0, "map": {}}

async def _get_id_name_map() -> Dict[str, str]:
    now = time.time()
    if _ID_NAME_CACHE["map"] and (now - _ID_NAME_CACHE["ts"] < 60):
        return _ID_NAME_CACHE["map"]
    mapping: Dict[str, str] = {}
    if not (PROTECT_HOST and IKEY):
        _ID_NAME_CACHE["map"] = mapping
        _ID_NAME_CACHE["ts"] = now
        return mapping
    async with httpx.AsyncClient(verify=VERIFY_TLS, timeout=20, follow_redirects=True) as cx:
        try:
            r = await cx.get(f"{PROTECT_HOST}/proxy/protect/integration/v1/cameras",
                             headers={"X-API-KEY": IKEY})
            if r.status_code == 200:
                for cam in r.json():
                    cid = cam.get("id")
                    nm  = (cam.get("name") or cam.get("displayName") or cam.get("channelName") or "").strip()
                    if cid and nm:
                        mapping[cid] = nm
        except Exception as e:
            LOG.warning(f"[ID→NAME] fetch failed: {e}")
    _ID_NAME_CACHE["map"] = mapping
    _ID_NAME_CACHE["ts"] = now
    return mapping

async def _resolve_camera_name(payload: Dict[str, Any]) -> Optional[str]:
    nm = _find_camera_name_in_payload(payload)
    if nm:
        return nm
    cid = _find_camera_id(payload)
    if not (isinstance(cid, str) and len(cid) == 24):
        cid = _extract_camera_id_from_urls(payload)
    return await _id_to_name(cid)

# -------------------- Webhook --------------------

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
        camera_name = await _resolve_camera_name(payload)
    if not camera_name and camera_id and len(camera_id) == 24:
        m = await _get_id_name_map()
        camera_name = m.get(camera_id)

    title = build_title(kind, vr, camera_name)
    await _maybe_escalate(vr, payload, ts_ms)
    await _notify(title=title, message=vr.notification_message, image_bytes=img, image_name=image_name)
    return {
        "ok": True,
        "summary": vr.notification_message,
        "camera": camera_name or camera_id or "unknown",
        "ts_ms": ts_ms,
    }

@app.post("/unifi-webhook")
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

    ts_ms = _find_timestamp_ms(payload)

    # *** EARLY camera name resolution (works for both data and url flows) ***
    camera_name = await _resolve_camera_name(payload)
    if not camera_name:
        urls = _list_image_urls(payload)
        cid_guess = _extract_camera_id_from_urls(payload)
        LOG.info(f"[NAME] urls={urls[:3]} extracted_cid={cid_guess!r}")

    smart_types = _extract_smart_types(payload)
    LOG.info(f"[SMART] uni_smart_types={sorted(list(smart_types))}")

    # 1) Thumbnail/data-image first
    src_kind, src_val = _pick_image_source(payload)
    if src_kind == "data":
        img = _data_url_to_bytes(src_val)
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
    camera_id = _find_camera_id(payload) or DEFAULT_CAMERA_ID
    if not camera_id:
        LOG.error("[WEBHOOK] no camera id found in payload and no DEFAULT_CAMERA_ID set")
        raise HTTPException(status_code=400, detail="No camera id found in webhook payload")

    jpeg = await get_snapshot_by_ts(camera_id=camera_id, ts_ms=ts_ms, verify_tls=VERIFY_TLS)
    return await _process_and_notify(
        jpeg, "snapshot.jpg", payload, smart_types, ts_ms, camera_name, camera_id=camera_id
    )
