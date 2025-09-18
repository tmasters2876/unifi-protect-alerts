# unifi.py — Integration API first, classic API fallback, with camera-id resolver

import os, time, re
from typing import Dict, Any
import httpx

class UnifiAuthError(Exception):
    pass

def _env():
    host   = (os.environ.get("PROTECT_HOST") or "").rstrip("/")
    ikey   = os.environ.get("PROTECT_INTEGRATION_KEY") or ""
    btoken = os.environ.get("PROTECT_API_KEY") or ""  # optional fallback (UniFi OS)
    if not host:
        raise UnifiAuthError("PROTECT_HOST is not set")
    if not ikey and not btoken:
        raise UnifiAuthError("Provide PROTECT_INTEGRATION_KEY (preferred) or PROTECT_API_KEY.")
    return host, ikey, btoken

async def _http_get(url: str, headers: dict, params: dict, verify_tls: bool) -> httpx.Response:
    async with httpx.AsyncClient(verify=verify_tls, timeout=20, follow_redirects=True) as client:
        return await client.get(url, headers=headers, params=params)

async def _http_post(url: str, headers: dict, data: bytes | None, verify_tls: bool) -> httpx.Response:
    async with httpx.AsyncClient(verify=verify_tls, timeout=20, follow_redirects=True) as client:
        return await client.post(url, headers=headers, content=data or b"")

# ---------------- Camera resolver (maps MAC/device → Integration id) ----------------
_CAM_CACHE = {"ts": 0.0, "map": {}}  # 30s cache
_MAC_RE = re.compile(r"^[0-9a-fA-F:]{12,17}$")

def _norm_mac(s: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", s or "").upper()

def _all_mac_variants(mac: str):
    m = mac.strip()
    no = m.replace(":", "")
    return {m, m.lower(), m.upper(), no, no.lower(), no.upper()}

def _deep_find_macs(o: Any):
    found = set()
    if isinstance(o, dict):
        for v in o.values():
            found |= _deep_find_macs(v)
    elif isinstance(o, list):
        for v in o:
            found |= _deep_find_macs(v)
    elif isinstance(o, str):
        s = o.replace("-", ":")
        if _MAC_RE.match(s):
            found.add(s)
    return found

async def _refresh_camera_map(verify_tls: bool = True):
    now = time.time()
    if _CAM_CACHE["map"] and (now - _CAM_CACHE["ts"] < 30):
        return

    host, ikey, btoken = _env()
    cmap: Dict[str, str] = {}

    # Integration list (preferred)
    if ikey:
        r = await _http_get(f"{host}/proxy/protect/integration/v1/cameras",
                            {"X-API-KEY": ikey}, {}, verify_tls)
        if r.status_code == 200:
            cams = r.json()
            for cam in cams:
                cid = str(cam.get("id") or "")
                if not cid: 
                    continue
                cmap[cid] = cid
                cmap[cid.lower()] = cid

                mac = (cam.get("mac") or cam.get("macAddress") or cam.get("mac_address")
                       or cam.get("deviceMac"))
                macs = set()
                if isinstance(mac, str):
                    macs.add(mac)
                macs |= _deep_find_macs(cam)  # pick up weird/nested macs

                for m in list(macs):
                    nm = _norm_mac(m)
                    if not nm:
                        continue
                    cmap[nm] = cid
                    colon = ":".join([nm[i:i+2] for i in range(0, len(nm), 2)])
                    cmap[colon.upper()] = cid
                    cmap[colon.lower()] = cid
        # non-200 is not fatal; we may still try classic

    # Optional classic list (Bearer) – your current Bearer returns 401, so this will be skipped/ignored
    if btoken:
        r = await _http_get(f"{host}/proxy/protect/api/cameras",
                            {"Authorization": f"Bearer {btoken}"}, {}, verify_tls)
        if r.status_code == 200:
            cams = r.json()
            for cam in cams:
                cid = str(cam.get("id") or "")
                if not cid:
                    continue
                cmap[cid] = cid
                cmap[cid.lower()] = cid
                mac = cam.get("mac")
                if isinstance(mac, str):
                    nm = _norm_mac(mac)
                    if nm:
                        cmap[nm] = cid
                        colon = ":".join([nm[i:i+2] for i in range(0, len(nm), 2)])
                        cmap[colon.upper()] = cid
                        cmap[colon.lower()] = cid

    if not cmap:
        raise UnifiAuthError("Could not fetch camera list from Protect (Integration/Classic both failed).")

    _CAM_CACHE["map"] = cmap
    _CAM_CACHE["ts"] = time.time()

async def resolve_camera_identifier(identifier: str, verify_tls: bool = True) -> str:
    if not identifier:
        raise UnifiAuthError("Empty camera identifier")

    now = time.time()
    if not _CAM_CACHE["map"] or (now - _CAM_CACHE["ts"] > 30):
        await _refresh_camera_map(verify_tls)

    cmap = _CAM_CACHE["map"]
    raw = identifier.strip()
    keys = [raw, raw.lower(), raw.upper()]
    nm = _norm_mac(raw)
    if nm:
        keys += [nm, ":".join([nm[i:i+2] for i in range(0, len(nm), 2)]).upper(),
                     ":".join([nm[i:i+2] for i in range(0, len(nm), 2)]).lower()]
    for k in keys:
        if k in cmap:
            return cmap[k]

    # refresh once and retry
    await _refresh_camera_map(verify_tls)
    cmap = _CAM_CACHE["map"]
    for k in keys:
        if k in cmap:
            return cmap[k]

    if len(raw) == 24:  # already an integration id
        return raw

    raise UnifiAuthError(f"Unknown camera identifier '{identifier}'. Not found in Protect camera list.")

# Expose the current camera map for debugging
async def get_camera_map(verify_tls: bool = True) -> Dict[str, str]:
    await _refresh_camera_map(verify_tls)
    return dict(_CAM_CACHE["map"])

# ---------------- Snapshot helpers ----------------
async def get_snapshot_by_ts(camera_id: str, ts_ms: int, verify_tls: bool = True) -> bytes:
    host, ikey, btoken = _env()
    resolved_id = await resolve_camera_identifier(camera_id, verify_tls=verify_tls)

    attempts = []

    if ikey:
        for pn in ("timestamp", "ts"):
            url = f"{host}/proxy/protect/integration/v1/cameras/{resolved_id}/snapshot"
            headers = {"X-API-KEY": ikey, "Accept": "image/*"}
            r = await _http_get(url, headers, {pn: str(ts_ms)}, verify_tls)
            if r.status_code == 200 and (r.headers.get("content-type","").lower().startswith("image/")):
                return r.content
            attempts.append(f"Integration {pn}: HTTP {r.status_code} {r.text[:200]!r}")

    if btoken:
        url = f"{host}/proxy/protect/api/cameras/{resolved_id}/snapshot"
        headers = {"Authorization": f"Bearer {btoken}", "Accept": "image/*"}
        r = await _http_get(url, headers, {"ts": str(ts_ms), "force": "true"}, verify_tls)
        if r.status_code == 200 and (r.headers.get("content-type","").lower().startswith("image/")):
            return r.content
        attempts.append(f"Classic ts: HTTP {r.status_code} {r.text[:200]!r}")

    raise UnifiAuthError("Snapshot failed; tried: " + " | ".join(attempts))

async def get_snapshot_now(camera_id: str, verify_tls: bool = True) -> bytes:
    host, ikey, btoken = _env()
    resolved_id = await resolve_camera_identifier(camera_id, verify_tls=verify_tls)

    if ikey:
        url = f"{host}/proxy/protect/integration/v1/cameras/{resolved_id}/snapshot"
        r = await _http_get(url, {"X-API-KEY": ikey, "Accept": "image/*"}, {}, verify_tls)
        if r.status_code == 200 and (r.headers.get("content-type","").lower().startswith("image/")):
            return r.content

    if btoken:
        url = f"{host}/proxy/protect/api/cameras/{resolved_id}/snapshot"
        r = await _http_get(url, {"Authorization": f"Bearer {btoken}", "Accept": "image/*"}, {}, verify_tls)
        if r.status_code == 200 and (r.headers.get("content-type","").lower().startswith("image/")):
            return r.content

    raise UnifiAuthError("Snapshot-now failed on both Integration and Classic APIs")

# ---------------- Inbound Alarm Trigger (Alarm Manager "Trigger Link") ----------------
async def fire_protect_trigger(trigger_url: str, verify_tls: bool = True) -> None:
    """
    Fire a Protect Alarm Manager trigger by POSTing to its 'Trigger Link'.
    Uses Integration API key if available, else UniFi OS bearer as fallback.
    """
    if not trigger_url:
        raise UnifiAuthError("Empty trigger_url")

    host, ikey, btoken = _env()
    headers = {}
    if ikey:
        headers["X-Api-Key"] = ikey      # Integration key (preferred for Alarm Manager)
    elif btoken:
        headers["Authorization"] = f"Bearer {btoken}"  # fallback if integration key isn't set

    r = await _http_post(trigger_url, headers, None, verify_tls)
    if r.status_code not in (200, 204):
        raise UnifiAuthError(f"Trigger POST failed: HTTP {r.status_code} {r.text[:200]!r}")

