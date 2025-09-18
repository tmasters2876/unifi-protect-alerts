#!/usr/bin/env python3
"""
UniFi Protect → AI Alerts (Integration API only, stdlib-only)

- No external deps: uses urllib/ssl/json only.
- Uses PROTECT_INTEGRATION_KEY for cameras, events, snapshots.
- Titles alerts with real camera name: "<Kind> Alert — <Camera>".

.env (same folder):
  PROTECT_HOST=https://192.168.200.43
  PROTECT_INTEGRATION_KEY=...
  VERIFY_TLS=false        # for self-signed during testing

Optional:
  CAMERA_FILTER=Pond,Front Door   # comma list OR regex (if no comma)
  EVENT_POLL_SECONDS=0.8
  MIN_ALERT_INTERVAL_SEC=15
"""

import os, re, time, json, ssl, urllib.request, urllib.parse, logging, asyncio
from typing import Any, Dict, List, Optional, Tuple

# -------------------- tiny .env loader --------------------
def _load_env(path: str = ".env") -> None:
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            k, v = s.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k and k not in os.environ:
                os.environ[k] = v

_load_env(".env")

# -------------------- env --------------------
PROTECT_HOST = (os.environ.get("PROTECT_HOST") or "").rstrip("/")
IKEY         = os.environ.get("PROTECT_INTEGRATION_KEY") or ""
VERIFY_TLS   = (os.environ.get("VERIFY_TLS", "true").lower() in ("1","true","yes","on"))

CAMERA_FILTER          = os.environ.get("CAMERA_FILTER") or ""
EVENT_POLL_SECONDS     = float(os.environ.get("EVENT_POLL_SECONDS", "0.8"))
MIN_ALERT_INTERVAL_SEC = int(os.environ.get("MIN_ALERT_INTERVAL_SEC", "15"))

if not (PROTECT_HOST and IKEY):
    raise SystemExit("Set PROTECT_HOST and PROTECT_INTEGRATION_KEY in .env")

# -------------------- your modules --------------------
from vision import analyze_image                 # bytes -> summary
from notify import send_alert, notify_available  # Pushover sender

# -------------------- logging --------------------
LOG = logging.getLogger("watcher.integration")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# -------------------- HTTP helpers (stdlib) --------------------
_CTX = ssl.create_default_context()
if not VERIFY_TLS:
    _CTX.check_hostname = False
    _CTX.verify_mode = ssl.CERT_NONE

def _req(url: str, headers: Dict[str, str] | None = None) -> urllib.request.Request:
    h = {"X-API-KEY": IKEY}
    if headers:
        h.update(headers)
    return urllib.request.Request(url, headers=h)

def _get_json(url: str) -> Any:
    with urllib.request.urlopen(_req(url), context=_CTX, timeout=20) as r:
        data = r.read()
    return json.loads(data.decode("utf-8", errors="ignore"))

def _get_bytes(url: str) -> bytes:
    with urllib.request.urlopen(_req(url), context=_CTX, timeout=30) as r:
        return r.read()

# -------------------- cameras --------------------
async def _fetch_cameras() -> Dict[str, str]:
    url = f"{PROTECT_HOST}/proxy/protect/integration/v1/cameras"
    cams = _get_json(url)
    mapping: Dict[str, str] = {}
    if isinstance(cams, list):
        for cam in cams:
            if not isinstance(cam, dict):
                continue
            cid = cam.get("id")
            nm  = (cam.get("name") or cam.get("displayName") or cam.get("channelName") or "").strip()
            if cid and nm:
                mapping[cid] = nm
    return mapping

def _compile_filter(all_names: List[str], spec: str):
    if not spec:
        return set(all_names), None
    if "," in spec:
        return {s.strip() for s in spec.split(",") if s.strip()}, None
    try:
        return None, re.compile(spec)
    except re.error:
        return {spec}, None

# -------------------- events --------------------
def _normalize_events(raw: Any) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    data = raw
    if isinstance(data, dict):
        for k in ("events", "items", "results", "data"):
            v = data.get(k)
            if isinstance(v, list):
                data = v
                break
    if isinstance(data, list):
        for e in data:
            if isinstance(e, dict):
                out.append(e)
    return out

def _extract_ts_ms(ev: Dict[str, Any]) -> Optional[int]:
    for k in ("timestamp","ts","start","startMs","timeMs","eventTime"):
        v = ev.get(k)
        if isinstance(v, (int, float)):
            x = int(v)
            return x if x >= 1_000_000_000_000 else x * 1000
    return None

def _extract_cid(ev: Dict[str, Any]) -> Optional[str]:
    return (
        (ev.get("camera") or {}).get("id")
        or ev.get("cameraId")
        or ev.get("camera")
        or (ev.get("resource") or {}).get("id")
    )

async def _fetch_events_since(since_ms: int, until_ms: Optional[int] = None) -> List[Dict[str, Any]]:
    base = f"{PROTECT_HOST}/proxy/protect/integration/v1/events"
    params_list = []
    if until_ms is not None:
        params_list += [
            {"start": since_ms,  "end": until_ms},
            {"startMs": since_ms,"endMs": until_ms},
        ]
    # Some firmwares only accept since
    params_list += [
        {"since": since_ms},
        {"since": since_ms, "limit": 200},
    ]
    for p in params_list:
        try:
            url = base + "?" + urllib.parse.urlencode(p)
            evs = _normalize_events(_get_json(url))
            if evs:
                return evs
        except Exception as e:
            LOG.warning("events fetch failed params=%s: %r", p, e)
    return []

# -------------------- snapshots --------------------
async def _snapshot_bytes(cam_id: str, ts_ms: int) -> bytes:
    q = urllib.parse.urlencode({"ts": ts_ms})
    url = f"{PROTECT_HOST}/proxy/protect/integration/v1/cameras/{cam_id}/snapshot?{q}"
    try:
        return _get_bytes(url)
    except Exception as e:
        LOG.warning("snapshot failed for %s: %r", cam_id, e)
        return b""

# -------------------- labeling --------------------
_VEH = ("vehicle","car","truck","van","suv","bike","bicycle","motorcycle","pickup")
_PKG = ("package","parcel","delivery","box")
_ANIMALS = ("raccoon","cat","dog","deer","fox","coyote","squirrel","bird","opossum","skunk")

def _kind_from_summary(summary: str) -> str:
    s = (summary or "").lower()
    if any(w in s for w in ("person","man","woman","intruder","visitor","someone")):
        return "Person"
    if any(w in s for w in _VEH):
        return "Vehicle"
    if any(w in s for w in _PKG):
        return "Package"
    for sp in _ANIMALS:
        if sp in s:
            return sp.capitalize()
    return "Alert"

async def _notify(title: str, message: str, image_bytes: bytes):
    if not notify_available():
        return
    try:
        try:
            await send_alert(title=title, message=message, image_bytes=image_bytes, image_name="snapshot.jpg")
        except TypeError:
            await send_alert(title=title, message=message)
    except Exception as e:
        LOG.error("notify failed: %r", e)

# -------------------- main loop --------------------
async def main():
    # 1) prime camera map + filter
    name_map = await _fetch_cameras()
    all_names = list(name_map.values())
    allowset, rx = _compile_filter(all_names, CAMERA_FILTER)

    LOG.info("Watcher (integration/stdlib) starting. Cameras=%d; filter=%s",
             len(name_map), CAMERA_FILTER or "<none>")

    last_alert_at: Dict[str, float] = {}
    seen_ids: set = set()

    # Start a bit in the past to catch recent events
    last_since = int(time.time() * 1000) - 20_000

    while True:
        try:
            now_ms = int(time.time() * 1000)
            evs = await _fetch_events_since(last_since, now_ms + 1)

            # refresh camera names every ~30s
            if int(time.time()) % 30 == 0:
                try:
                    name_map = await _fetch_cameras()
                except Exception:
                    pass

            for ev in evs:
                eid = ev.get("id") or ev.get("_id") or f"{_extract_ts_ms(ev)}:{_extract_cid(ev)}"
                if eid in seen_ids:
                    continue
                seen_ids.add(eid)

                cid = _extract_cid(ev)
                if not (isinstance(cid, str) and len(cid) == 24):
                    continue
                cam_name = name_map.get(cid, cid)

                # optional camera filter by name
                if allowset is not None and cam_name not in allowset:
                    continue
                if rx is not None and not rx.search(cam_name):
                    continue

                # debounce per camera
                if time.time() - last_alert_at.get(cid, 0) < MIN_ALERT_INTERVAL_SEC:
                    continue

                ts = _extract_ts_ms(ev) or now_ms
                jpeg = await _snapshot_bytes(cid, ts)
                if not jpeg:
                    last_alert_at[cid] = time.time()
                    continue

                summary = await analyze_image(jpeg)
                title = f"{_kind_from_summary(summary)} Alert — {cam_name}"
                await _notify(title=title, message=summary, image_bytes=jpeg)
                last_alert_at[cid] = time.time()
                LOG.info("[ALERT] %s :: %s", cam_name, title)

            if evs:
                last_since = max(last_since, max([_extract_ts_ms(e) or last_since for e in evs]))

            await asyncio.sleep(EVENT_POLL_SECONDS)

        except asyncio.CancelledError:
            break
        except Exception as e:
            LOG.error("loop error: %r", e)
            await asyncio.sleep(1.0)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
