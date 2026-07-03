# payload.py — parses a UniFi Protect webhook payload: camera id/name, timestamp, image candidates
import base64
import re
import time
import urllib.parse as _urlparse
from urllib.parse import urlparse, parse_qs
from typing import Any, Dict, Iterable, Optional, Set, Tuple

from config import PROTECT_HOST

# Extract a 24-hex camera id from any thumbnail/snapshot URL
_HEX24 = re.compile(r'(?i)[0-9a-f]{24}')


def absolute_url(u: str) -> str:
    if not isinstance(u, str) or not u:
        return ""
    if u.startswith("http://") or u.startswith("https://"):
        return u
    if u.startswith("/"):
        return f"{PROTECT_HOST}{u}"
    return u


def data_url_to_bytes(s: str) -> bytes:
    try:
        _, b64 = s.split(",", 1)
        return base64.b64decode(b64)
    except Exception:
        return b""


def iter_image_candidates(payload: Any) -> Iterable[Tuple[str, str]]:
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


def list_image_urls(payload: Any):
    urls = []
    for kind, val in iter_image_candidates(payload):
        if kind == "url":
            urls.append(absolute_url(val))
    return urls


def pick_image_source(payload: Any) -> Tuple[Optional[str], Optional[str]]:
    url_rel = None
    for kind, val in iter_image_candidates(payload):
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


def extract_camera_id_from_urls(payload: Any) -> Optional[str]:
    for kind, val in iter_image_candidates(payload):
        if kind != "url":
            continue
        u = absolute_url(val)
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


def _first_nonempty(*vals) -> Optional[Any]:
    for v in vals:
        if v is not None and v != "":
            return v
    return None


def find_camera_id(payload: Dict[str, Any]) -> Optional[str]:
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


def find_camera_name_in_payload(payload: Dict[str, Any]) -> Optional[str]:
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


def find_timestamp_ms(payload: Dict[str, Any]) -> int:
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


def extract_smart_types(payload: Dict[str, Any]) -> Set[str]:
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
