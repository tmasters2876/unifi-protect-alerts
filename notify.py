# notify.py — Pushover with optional image attachment
import os
from typing import Optional
import httpx

PUSHOVER_USER_KEY = os.getenv("PUSHOVER_USER_KEY")
PUSHOVER_APP_TOKEN = os.getenv("PUSHOVER_APP_TOKEN")

_client: Optional[httpx.AsyncClient] = None


def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=20)
    return _client


async def aclose_client():
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


def notify_available() -> bool:
    return bool(PUSHOVER_USER_KEY and PUSHOVER_APP_TOKEN)

async def send_alert(title: str, message: str, image_bytes: bytes | None = None, image_name: str = "alert.jpg"):
    if not notify_available():
        return

    data = {
        "token": PUSHOVER_APP_TOKEN,
        "user": PUSHOVER_USER_KEY,
        "title": title or "Alert",
        "message": message or "",
        "priority": "0",
    }

    files = None
    if image_bytes:
        # Pushover supports jpeg/png/gif up to ~2.5MB
        # Default to jpeg content-type; Pushover will sniff.
        files = {"attachment": (image_name, image_bytes, "image/jpeg")}

    cx = _get_client()
    r = await cx.post("https://api.pushover.net/1/messages.json", data=data, files=files)
    r.raise_for_status()
    # optional: return r.json()
