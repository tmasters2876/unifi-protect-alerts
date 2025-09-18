# main.py
import os, base64, time, asyncio
import httpx
import logging
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")

from typing import Any, Dict, Optional, Tuple, Iterable, Set, List

from fastapi import FastAPI, UploadFile, File, Request, HTTPException
from pydantic import BaseModel

# URL + regex helpers (for cameraId extraction from thumbnail URLs)
import urllib.parse as _urlparse
from urllib.parse import urlparse, parse_qs
import re as _re

from unifi import get_snapshot_by_ts, UnifiAuthError, get_camera_map
from vision import analyze_image
from notify import send_alert, notify_available

# ---------- Optional uiprotect (unofficial SDK) ----------
_HAS_UIP = False
try:
    # If not installed, we keep working with Integration API only.
    from uiprotect import ProtectApiClient  # type: ignore
    _HAS_UIP = True
except Exception:
    _HAS_UIP = False

VERIFY_TLS = os.environ.get("VERIFY_TLS", "true").lower() == "true"
SHARED_SECRET = os.environ.get("ALERT_SHARED_SECRET", "")
DEFAULT_CAMERA_ID = os.environ.get("DEFAULT_CAMERA_ID")
PROTECT_HOST = (os.environ.get("PROTECT_HOST") or "").rstrip("/")
IKEY = os.environ.get("PROTECT_INTEGRATION_KEY") or ""
BTOKEN = os.environ.get("PROTECT_API_KEY") or ""  # optional for classic/SDK
LOG = logging.getLogger("uvicorn.error")

from event_listener import attach_event_listener, name_from_ts  # <— listener (drop-in)

app = FastAPI(title="UniFi AI Alerts")
attach_event_listener(app)  # <— one-liner wiring

class ProtectAlarm(BaseModel):
    alarm: Dict[str, Any]
    timestamp: int

# -------------------------------------------------------------------
# Optional: uiprotect client (only used for ID→Name lookup fallback)
# -------------------------------------------------------------------
_UIP_CACHE: Dict[str, Any] = {"client": None, "ts": 0.0}

def _host_without_scheme(h: str) -> str:
    if not h:
        return ""
    if h.startswith("https://"):
        return h[len("https://"):]
    if h.startswith("http://"):
        return h[len("http://"):]
    return h

async def _ensure_uiprotect() -> Optional["ProtectApiClient"]:
    """Create/refresh a uiprotect client if package is installed and PAT exists."""
    if not (_HAS_UIP and BTOKEN and PROTECT_HOST):
        return None
    now = time.time()
    c = _UIP_CACHE.get("client")
    if c and (now - _UIP_CACHE.get("ts", 0.0) < 60):
        return c
    try:
        host = _host_without_scheme(PROTECT_HOST)
        # uiprotect defaults to 443; we pass blank username/password and use api_key.
        client = ProtectApiClient(host, 443, "", "", api_key=BTOKEN, verify_ssl=VERIFY_TLS)  # type: ignore
        await client.update()  # populate bootstrap
        _UIP_CACHE["client"] = client
        _UIP_CACHE["ts"] = now
        LOG.info("[UIPROTECT] client initialized OK (bootstrap loaded)")
        return client
    except Exception as e:
        LOG.warning(f"[UIPROTECT] init failed: {e}")
        _UIP_CACHE["client"] = None
        return None

async def _uip_id_to_name(cid: Optional[str]) -> Optional[str]:
    """Try to map 24-hex camera id to friendly name via uiprotect bootstrap."""
    if not (cid and isinstance(cid, str) and len(cid) == 24):
        return None
    client = await _ensure_uiprotect()
    if not client:
        return None
    try:
        bs = getattr(client, "bootstrap", None)
        cams = getattr(bs, "cameras", None)
        if isinstance(cams, dict) and cid in cams:
            nm = getattr(cams[cid], "name", None)
            if isinstance(nm, str) and nm.strip():
                return nm.strip()
    except Exception as e:
        LOG.debug(f"[UIPROTECT] id→name lookup failed for {cid}: {e}")
    return None

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
        "has_uiprotect": _HAS_UIP,
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
    # If uiprotect is active, also show a couple names from bootstrap
    extra = {}
    if await _ensure_uiprotect():
        try:
            cams = _UIP_CACHE["client"].bootstrap.cameras  # type: ignore
            for i, (cid, cam) in enumerate(cams.items()):
                if i >= 5: break
                extra[cid] = getattr(cam, "name", "")
        except Exception:
            pass
    return {"count": len(m), "sample": out, "uiprotect_sample": extra}

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
    cid_from_deep = await _deep_find_integration_id(payload)
    name_from_payload = await _id_to_name(cid_payload)
    name_from_url = await _id_to_name(cid_from_url)
    name_from_deep = await _id_to_name(cid_from_deep)
    # uiprotect extras
    name_from_payload_uip = await _uip_id_to_name(cid_payload)
    name_from_url_uip = await _uip_id_to_name(cid_from_url)
    name_from_deep_uip = await _uip_id_to_name(cid_from_deep)
    m = await _get_id_name_map()
    return {
        "image_urls": urls,
        "cid_in_payload": cid_payload,
        "cid_from_url": cid_from_url,
        "cid_from_deep": cid_from_deep,
        "name_from_payload": name_from_payload,
        "name_from_url": name_from_url,
        "name_from_deep": name_from_deep,
        "id_name_map_size": len(m),
        "uiprotect": {
            "enabled": bool(await _ensure_uiprotect()),
            "name_from_payload": name_from_payload_uip,
            "name_from_url": name_from_url_uip,
            "name_from_deep": name_from_deep_uip,
        }
    }

@app.get("/debug/events")
async def debug_events(ts_ms: Optional[int] = None, window_ms: int = 8000):
    t = ts_ms or int(time.time() * 1000)
    names, ids = await _guess_cameras_from_events(t, window_ms=window_ms)
    return {"ts_ms": t, "window_ms": window_ms, "names": names, "ids": ids}

# -------------------- Helpers --------------------

# Extract a 24-hex camera id from any thumbnail/snapshot URL
_HEX24 = _re.compile(r'(?i)[0-9a-f]{24}')

def _list_image_urls(payload: Any) -> List[str]:
    urls: List[str] = []
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

        # Explicit query params first
        for key in ("cameraId", "camera", "id", "entityId"):
            vlist = qs.get(key) or qs.get(key.lower())
            if vlist:
                for v in vlist:
                    if isinstance(v, str) and _HEX24.fullmatch(v):
                        return v

        # Scan path segments like /.../cameras/<24hex>/snapshot
        for seg in parsed.path.split("/"):
            if _HEX24.fullmatch(seg):
                return seg

        # Final fallback: any 24-hex anywhere in the URL
        m = _HEX24.search(_urlparse.unquote(u))
        if m:
            return m.group(0)
    return None

async def _id_to_name(cid: Optional[str]) -> Optional[str]:
    """Integration map first, then uiprotect fallback (if enabled)."""
    if isinstance(cid, str) and len(cid) == 24:
        m = await _get_id_name_map()
        nm = m.get(cid)
        if nm:
            return nm
        # fallback via uiprotect bootstrap
        nm2 = await _uip_id_to_name(cid)
        if nm2:
            return nm2
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

def _coerce_to_ms(v: float | int) -> Optional[int]:
    try:
        x = float(v)
        if x >= 1_000_000_000_000:   # ms
            return int(x)
        if x >= 1_000_000_000:       # seconds
            return int(x * 1000)
    except Exception:
        pass
    return None

def _find_timestamp_ms(payload: Dict[str, Any]) -> int:
    import datetime as dt
    for k in ["timestamp","ts","timeMs","time_ms"]:
        v = payload.get(k)
        if isinstance(v, (int, float)):
            ms = _coerce_to_ms(v)
            if ms:
                return ms
    for parent in ["event","alarm","trigger"]:
        obj = payload.get(parent)
        if isinstance(obj, dict):
            for k in ["timestamp","ts","triggeredAt","when","start","startTime"]:
                v = obj.get(k)
                if isinstance(v, (int, float)):
                    ms = _coerce_to_ms(v)
                    if ms:
                        return ms
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
    """
    Walk payload and yield ANY string that looks like a URL (or data:image/...).
    The fetch step will filter non-image URLs by content-type.
    """
    QUEUE = [payload]
    while QUEUE:
        node = QUEUE.pop(0)

        if isinstance(node, dict):
            for _, v in node.items():
                if isinstance(v, (dict, list)):
                    QUEUE.append(v)
                elif isinstance(v, str):
                    vs = v.strip()
                    if vs.startswith("data:image/"):
                        yield ("data", vs)
                    elif vs.startswith("http://") or vs.startswith("https://") or vs.startswith("/"):
                        yield ("url", vs)

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

def _animal_from_summary(summary: str) -> Optional[str]:
    s = (summary or "").lower()
    for kw in ("raccoon","cat","dog","fox","deer","bear","coyote","squirrel","bird","opossum","skunk"):
        if kw in s:
            return kw.capitalize()
    return None

_VEH = ("vehicle","car","truck","suv","van","jeep","motorcycle","bike","bicycle","pickup")
_PKG = ("package","parcel","box","delivery","ups","fedex","usps","dhl")

def _kind_label(types: Set[str], summary: Optional[str]) -> str:
    if "person" in types:  return "Person"
    if "vehicle" in types: return "Vehicle"
    if "package" in types: return "Package"
    if "animal" in types:  return _animal_from_summary(summary or "") or "Animal"
    s = (summary or "").lower()
    if any(w in s for w in ("person","man","woman","individual","someone","intruder","visitor")):
        return "Person"
    if any(w in s for w in _VEH): return "Vehicle"
    if any(w in s for w in _PKG): return "Package"
    sp = _animal_from_summary(summary or "")
    if sp: return sp
    return "Alert"

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

# ---- deep 24-hex scan anywhere in payload, then validate against id→name map
async def _deep_find_integration_id(payload: Any) -> Optional[str]:
    m = await _get_id_name_map()
    if not m:
        return None
    QUEUE: List[Any] = [payload]
    while QUEUE:
        node = QUEUE.pop(0)
        if isinstance(node, dict):
            for v in node.values():
                QUEUE.append(v)
        elif isinstance(node, list):
            for v in node:
                QUEUE.append(v)
        elif isinstance(node, str):
            s = _urlparse.unquote(node)
            for match in _HEX24.findall(s):
                cid = match.lower()
                for key in (cid, cid.upper()):
                    if key in m:
                        return key
    return None

async def _resolve_camera_name(payload: Dict[str, Any]) -> Optional[str]:
    # 1) Friendly name in payload?
    nm = _find_camera_name_in_payload(payload)
    if nm:
        LOG.info("[NAME] method=payload-name name=%s", nm)
        return nm

    # 2) 24-hex id in payload fields?
    cid = _find_camera_id(payload)
    if isinstance(cid, str) and len(cid) == 24:
        name = await _id_to_name(cid)
        if name:
            LOG.info("[NAME] method=payload-id cid=%s name=%s", cid, name)
            return name

    # 3) 24-hex id inside any URL?
    cid = _extract_camera_id_from_urls(payload)
    if cid:
        name = await _id_to_name(cid)
        if name:
            LOG.info("[NAME] method=url cid=%s name=%s", cid, name)
            return name

    # 4) **Deep scan**: any 24-hex anywhere in the payload that matches a known camera id
    cid = await _deep_find_integration_id(payload)
    if cid:
        name = await _id_to_name(cid)
        if name:
            LOG.info("[NAME] method=deep cid=%s name=%s", cid, name)
            return name

    LOG.info("[NAME] method=none (no id/name discovered)")
    return None

# --- Event correlation fallback (Integration API) ---
async def _guess_cameras_from_events(ts_ms: int, window_ms: int = 8000) -> Tuple[List[str], List[str]]:
    """
    Ask Protect for events around the webhook timestamp and extract camera ids.
    Returns (camera_names, camera_ids). Uses Integration API (X-API-KEY) only.
    """
    if not (PROTECT_HOST and IKEY and ts_ms):
        return ([], [])
    url = f"{PROTECT_HOST}/proxy/protect/integration/v1/events"

    param_variants = [
        {"start": ts_ms - window_ms, "end": ts_ms + window_ms},
        {"since": ts_ms - window_ms, "until": ts_ms + window_ms},
        {"startMs": ts_ms - window_ms, "endMs": ts_ms + window_ms},
    ]

    ids: set[str] = set()
    async with httpx.AsyncClient(verify=VERIFY_TLS, timeout=15, follow_redirects=True) as cx:
        for params in param_variants:
            try:
                r = await cx.get(url, headers={"X-API-KEY": IKEY}, params=params)
                if r.status_code != 200:
                    continue
                evs = r.json()
                if not isinstance(evs, list):
                    continue
                for e in evs:
                    cid = (
                        (e.get("camera") or {}).get("id")
                        or e.get("cameraId")
                        or e.get("camera")
                        or (e.get("resource") or {}).get("id")
                    )
                    if isinstance(cid, str) and len(cid) == 24:
                        ids.add(cid)
                if ids:
                    break
            except Exception as ex:
                LOG.warning(f"[EVENTS] fetch failed params={params}: {ex}")

    if not ids:
        return ([], [])

    name_map = await _get_id_name_map()
    names = [name_map.get(cid, cid) for cid in ids]
    return (names, list(ids))

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
    LOG.info(f"[TS] using ts_ms={ts_ms}")

    # Early name resolution (payload → URL → deep). If still unknown: correlate.
    camera_name = await _resolve_camera_name(payload)
    smart_types = _extract_smart_types(payload)

    correlated_ids: List[str] = []
    if not camera_name:
        # super-lightweight local cache match (no network at webhook time)
        ev_name, ev_id = await name_from_ts(ts_ms)
        if ev_name:
            camera_name = ev_name
            if ev_id:
                correlated_ids = [ev_id]
            LOG.info(f"[NAME] method=events-cache name={camera_name} id={ev_id}")
        else:
            # existing online correlation fallback
            names, correlated_ids = await _guess_cameras_from_events(ts_ms)
            if names:
                camera_name = ", ".join(sorted(names))
                LOG.info(f"[NAME] method=events names={camera_name} ids={correlated_ids}")
            else:
                LOG.info("[NAME] method=none (no id/name discovered even via events)")

    # 1) Thumbnail/data-image first
    src_kind, src_val = _pick_image_source(payload)
    if src_kind == "data":
        img = _data_url_to_bytes(src_val)
        if img:
            summary = await analyze_image(img)
            kind = _kind_label(smart_types, summary)
            title = f"{kind} Alert" + (f" — {camera_name}" if camera_name else "")
            await _notify(title=title, message=summary, image_bytes=img, image_name="thumb.jpg")
            return {"ok": True, "summary": summary, "camera": camera_name or "unknown", "ts_ms": ts_ms}
        else:
            LOG.warning("[WEBHOOK] data:image present but could not decode; falling back")

    if src_kind == "url":
        img, ctype, how = await _fetch_image_url(src_val)
        if ctype.startswith("image/") and img:
            if not camera_name:
                # belt-and-suspenders: try again from URL
                camera_name = await _id_to_name(_extract_camera_id_from_urls(payload))
            LOG.info(f"[WEBHOOK] using thumbnail ({ctype}, auth={how}, bytes={len(img)})")
            summary = await analyze_image(img)
            kind = _kind_label(smart_types, summary)
            title = f"{kind} Alert" + (f" — {camera_name}" if camera_name else "")
            await _notify(title=title, message=summary, image_bytes=img, image_name="thumb.jpg")
            return {"ok": True, "summary": summary, "camera": camera_name or "unknown", "ts_ms": ts_ms}
        else:
            LOG.warning(f"[WEBHOOK] thumbnail not usable (ctype={ctype}); will try snapshot")

    # 2) Snapshot fallback
    camera_id = _find_camera_id(payload) or (correlated_ids[0] if len(correlated_ids) == 1 else None) or DEFAULT_CAMERA_ID
    if not camera_id:
        LOG.error("[WEBHOOK] no camera id found in payload, no correlated id, and no DEFAULT_CAMERA_ID set")
        raise HTTPException(status_code=400, detail="No camera id found in webhook payload")

    jpeg = await get_snapshot_by_ts(camera_id=camera_id, ts_ms=ts_ms, verify_tls=VERIFY_TLS)
    summary = await analyze_image(jpeg)
    kind = _kind_label(smart_types, summary)

    # If we still don't have a name but we have a 24-hex id, map it now (Integration → uiprotect fallback).
    if not camera_name and isinstance(camera_id, str) and len(camera_id) == 24:
        camera_name = await _id_to_name(camera_id)

    title = f"{kind} Alert" + (f" — {camera_name}" if camera_name else "")
    await _notify(title=title, message=summary, image_bytes=jpeg, image_name="snapshot.jpg")

    return {"ok": True, "summary": summary, "camera": camera_name or camera_id, "ts_ms": ts_ms}
