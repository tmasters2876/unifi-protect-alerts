# UniFi Protect → AI Alerts (FastAPI)

Turn vague UniFi Protect alerts into useful, human-readable notifications.

**Flow:** UniFi Protect (Alarm → Custom Webhook) → FastAPI → snapshot fetch → OpenAI Vision → Pushover (or console).

## Quick start

### 1) Env
Copy `.env.example` to `.env` and fill values:

```bash
cp .env.example .env
```

- `OPENAI_API_KEY`: OpenAI API key (Vision capable model like `gpt-4o-mini`).
- `PROTECT_HOST`: e.g., `https://udm-se.local` or `https://unvr.local` (must be reachable from the server).
- `PROTECT_API_KEY`: UniFi OS API token (preferred), or set `PROTECT_USERNAME`/`PROTECT_PASSWORD`.
- `PUSHOVER_USER_KEY`, `PUSHOVER_APP_TOKEN`: optional; if omitted, messages are printed to stdout.
- `ALERT_SHARED_SECRET`: any random string; set the same header in Protect webhook.
- `VERIFY_TLS`: `true` (default) or `false` if your UniFi box has self-signed certs.

### 2) Run (local)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -U pip
pip install -e .
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

### 3) Expose & configure UniFi Protect

- Expose `http(s)://<your host>:8080/unifi-webhook` (ngrok, reverse proxy, or public host).
- In **Protect → Alarm Manager → (Alarm) → Actions → Add Action → Webhook → Custom Webhook**:
  - Method: **POST**
  - URL: `https://<public-host>/unifi-webhook`
  - Headers: `x-alert-secret: <your ALERT_SHARED_SECRET>`
- Trigger a test alarm and watch the server logs.

### 4) Docker (optional)

```bash
docker build -t unifi-ai-alerts .
docker run --env-file .env -p 8080:8080 unifi-ai-alerts
```

## Endpoints

- `POST /unifi-webhook` – receives Protect webhook, fetches camera snapshot, runs OpenAI, pushes alert.
- `GET /health` – health probe.
- `POST /_dev/mock` – quick testing: upload a local JPEG and get an AI summary (bypasses Protect).

## Notes

- Snapshot fetching uses the UniFi OS proxy path: `/proxy/protect/api/cameras/{id}/snapshot?ts=...&force=true`.
- If your webhook payload lacks camera id, you can set `DEFAULT_CAMERA_ID` in `.env` or adjust parsing in `main.py`.
- Costs: use `gpt-4o-mini` for most alerts; escalate to larger models only on “important” classifications.
