# event_listener.py
import os, time, json, asyncio, logging
from pathlib import Path
from typing import Dict, List, Any
import httpx
from dotenv import load_dotenv

# ------------------ env ------------------
ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

PROTECT_HOST = (os.getenv("PROTECT_HOST") or "").rstrip("/")
IKEY = os.getenv("PROTECT_INTEGRATION_KEY") or ""
VERIFY_TLS = (os.getenv("VERIFY_TLS", "true").lower() == "true")

# how many events we retain in memory
MEM_CAP = int(os.getenv("EVENT_CACHE_SIZE", "200"))
POLL_SEC = float(os.getenv("EVENTS_POLL_SECONDS", "2.0"))   # low impact
NAME_REFRESH_SEC = float(os.getenv("NAMES_REFRESH_SECONDS", "60"))

LOG = logging.getLogger("listener")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# ------------------ state ------------------
event_ring: List[Dict[str, Any]] = []
id_to_name: Dict[str, str] = {}
last_names_refresh = 0.0

def _push_event(e: Dict[str, Any]):
    event_ring.append(e)
    if len(event_ring) > MEM_CAP:
        del event_ring[: len(event_ring) - MEM_CAP]

async def _fetch_names():
    """Refresh id->name via Integration API. Writes id_to_name.json for other processes to use."""
    global id_to_name
    if not (PROTECT_HOST and IKEY):
        return
    url = f"{PROTECT_HOST}/proxy/protect/integration/v1/cameras"
    try:
        async with httpx.AsyncClient(verify=VERIFY_TLS, timeout=15) as cx:
            r = await cx.get(url, headers={"X-API-KEY": IKEY})
            if r.status_code != 200:
                LOG.warning("names fetch %s: %s", r.status_code, r.text[:150])
                return
            mapping: Dict[str, str] = {}
            for cam in r.json():
                cid = cam.get("id")
                nm = (cam.get("name") or cam.get("displayName") or cam.get("channelName") or "").strip()
                if cid and nm:
                    mapping[cid] = nm
            if mapping:
                id_to_name = mapping
                # dump to a file other parts can read (e.g., your main)
                with open(ROOT / "id_to_name.json", "w") as f:
                    json.dump(mapping, f, indent=2, sort_keys=True)
                LOG.info("camera names refreshed: %d", len(mapping))
    except Exception as e:
        LOG.warning("names fetch failed: %r", e)

def _maybe_extract_cam_id(ev: Dict[str, Any]) -> str | None:
    # Common spots
    cid = (
        (ev.get("camera") or {}).get("id")
        or ev.get("cameraId")
        or ev.get("camera")
        or (ev.get("resource") or {}).get("id")
    )
    if isinstance(cid, str) and len(cid) == 24:
        return cid
    return None

async def _poll_events():
    """
    Poll Integration events endpoint in a conservative way.
    If your NVR returns 404 for unsupported param shape, we just back off and continue.
    """
    if not (PROTECT_HOST and IKEY):
        LOG.error("Missing PROTECT_HOST or PROTECT_INTEGRATION_KEY; cannot poll")
        return

    base = f"{PROTECT_HOST}/proxy/protect/integration/v1/events"
    params_variants = [
        # new-ish windowed style
        lambda now_ms: {"start": now_ms - 4000, "end": now_ms + 1000},
        lambda now_ms: {"startMs": now_ms - 4000, "endMs": now_ms + 1000},
        # since + limit style
        lambda now_ms: {"since": now_ms - 5000},
        lambda now_ms: {"since": now_ms - 5000, "limit": 200},
    ]

    backoff = 1.0
    while True:
        now_ms = int(time.time() * 1000)
        got_any = False
        async with httpx.AsyncClient(verify=VERIFY_TLS, timeout=15) as cx:
            for build in params_variants:
                params = build(now_ms)
                try:
                    r = await cx.get(base, headers={"X-API-KEY": IKEY}, params=params)
                    if r.status_code == 200:
                        data = r.json()
                        if isinstance(data, list):
                            # store a condensed copy
                            for ev in data:
                                e_small = {
                                    "ts": ev.get("start") or ev.get("timestamp") or ev.get("when") or now_ms,
                                    "type": ev.get("type") or ev.get("eventType"),
                                    "cameraId": _maybe_extract_cam_id(ev),
                                }
                                _push_event(e_small)
                            got_any = got_any or bool(data)
                        else:
                            LOG.debug("events response not a list")
                    elif r.status_code in (404, 429):
                        LOG.warning("events fetch failed params=%s: %r", params, httpx.HTTPError(f"{r.status_code}: {r.reason_phrase}"))
                    else:
                        LOG.debug("events %s: %s", r.status_code, r.text[:120])
                except Exception as ex:
                    LOG.warning("events fetch exception params=%s: %r", params, ex)
        # backoff / pacing
        await asyncio.sleep(POLL_SEC if got_any else max(POLL_SEC, backoff))
        backoff = min(backoff * 1.2, 3.0)

async def _names_refresher():
    global last_names_refresh
    while True:
        now = time.time()
        if now - last_names_refresh > NAME_REFRESH_SEC:
            await _fetch_names()
            last_names_refresh = now
        await asyncio.sleep(1.0)

async def main():
    LOG.info("Listener starting. host=%s verify_tls=%s", PROTECT_HOST, VERIFY_TLS)
    await _fetch_names()
    await asyncio.gather(_poll_events(), _names_refresher())

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
