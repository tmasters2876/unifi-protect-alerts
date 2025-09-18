# notify.py — Pushover with optional image attachment yes
import os
import httpx

PUSHOVER_USER_KEY = os.getenv("PUSHOVER_USER_KEY")
PUSHOVER_APP_TOKEN = os.getenv("PUSHOVER_APP_TOKEN")

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

    async with httpx.AsyncClient(timeout=20) as cx:
        r = await cx.post("https://api.pushover.net/1/messages.json", data=data, files=files)
        r.raise_for_status()
        # optional: return r.json()
