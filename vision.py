# vision.py
import os, base64, httpx

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")

PROMPT = (
    "You are a strict home-security analyst. Write one concise paragraph for a push notification.\n"
    "Report only what is relevant: people, vehicles, packages, animals; counts, colors, notable actions.\n"
    "WEAPONS: if a gun/knife/other weapon is clearly visible, say it early and name the type (e.g., shotgun, pistol, rifle, knife). "
    "If uncertain, say 'object resembling a gun/knife' or 'unclear object'. Do not guess.\n"
    "Direction: avoid 'left/right'. Use 'toward/away from camera' or 'toward the door/yard' only if obvious.\n"
    "Items carried: mention only if clearly visible; avoid guessing handedness unless unambiguous.\n"
    "Avoid listing things that are not present (e.g., 'no weapons' or 'no packages') when a person/vehicle/animal is already described."
    "Only mention things that are present; do not list absences when something relevant is visible. "
    "If nothing relevant is visible, say so briefly.\n"
    "Do NOT start with 'Alert:'; write a plain sentence. No speculation—prefer 'unclear' when not confident."
)

async def analyze_image(jpeg_bytes: bytes) -> str:
    if not OPENAI_API_KEY:
        return "[OpenAI key missing]"

    b64 = base64.b64encode(jpeg_bytes).decode()
    image_url = f"data:image/jpeg;base64,{b64}"

    body = {
        "model": "gpt-4o-mini",
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": PROMPT},
                {"type": "image_url", "image_url": {"url": image_url}}
            ],
        }],
        "temperature": 0.2,
    }

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json",
            },
            json=body,
        )

        # Helpful debugging on 4xx:
        if r.status_code >= 400:
            try:
                err = r.json()
            except Exception:
                err = {"error": r.text}
            raise RuntimeError(f"OpenAI error {r.status_code}: {err}")

        data = r.json()

    return data["choices"][0]["message"]["content"]
