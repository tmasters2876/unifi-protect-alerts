# CLAUDE.md — unifi-protect-alerts

## What this project does

FastAPI webhook server that receives UniFi Protect alarm events, fetches a camera snapshot or thumbnail, runs it through OpenAI Vision (`gpt-4o-mini`), and pushes a human-readable Pushover notification with the image attached.

**Flow:** UniFi Protect Alarm Webhook → `POST /unifi-webhook` → image fetch → OpenAI Vision → Pushover (or stdout if not configured)

---

## Stack

| Layer | Technology |
|---|---|
| Language | Python 3.11 |
| Web framework | FastAPI + Uvicorn |
| HTTP client | httpx (async) |
| AI vision | OpenAI API (`gpt-4o-mini`) via raw httpx (no SDK) |
| Notifications | Pushover REST API |
| Config | python-dotenv, `.env` file |
| Packaging | setuptools via `pyproject.toml` |
| Linting | ruff (dev dependency) |
| Deployment | Docker / docker-compose (targets Synology NAS at `/volume1/unifi-ai`) |

---

## Project structure

```
unifi-protect-alerts/
├── main.py              # FastAPI app, all webhook logic, label helpers
├── unifi.py             # UniFi Protect API client (Integration + Classic)
├── vision.py            # OpenAI Vision wrapper
├── notify.py            # Pushover notification sender
├── pyproject.toml       # Dependencies and build config
├── Dockerfile           # python:3.11-slim, installs package, runs uvicorn (flat-file layout)
├── .dockerignore        # Excludes venvs, Archive/, scripts/, tests/, .env from the image
├── docker-compose.yaml  # Synology NAS deployment (port 18080→8080), mounts ./logs
├── id_to_name.json      # Optional manual camera id→name override map
├── mac_to_name.json     # Optional MAC→name override map
├── probe_integration.py # One-off debug probe (reads .env, no hardcoded secrets)
├── scripts/
│   └── probe_unvr.py    # Stdlib-only camera discovery probe; writes id_to_name.json/mac_to_name.json
├── Archive/             # Old versions of main.py (not active)
├── logs/                # RotatingFileHandler output (gitignored, mounted on NAS)
└── .env                 # Local secrets (never commit)
```

---

## Virtual environment setup (local dev)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .              # installs all runtime deps from pyproject.toml
pip install -e ".[dev]"       # also installs ruff
```

There is a top-level `venv/` at `~/Projects/venv` — ignore it; this project uses its own `.venv`.

---

## Running locally

```bash
source .venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8080 --reload
```

The Dockerfile now matches this flat-file layout (`uvicorn main:app`, `COPY . .` filtered by `.dockerignore`).

---

## Environment variables (`.env`)

| Variable | Required | Description |
|---|---|---|
| `OPENAI_API_KEY` | Yes | OpenAI key with Vision access |
| `PROTECT_HOST` | Yes | e.g. `https://udm-se.local` — must be reachable from the server |
| `PROTECT_INTEGRATION_KEY` | Preferred | UniFi OS Integration API key (`X-API-KEY`) |
| `PROTECT_API_KEY` | Fallback | UniFi OS Bearer token (classic API) |
| `PUSHOVER_USER_KEY` | Optional | Pushover user key; if missing, alerts log to stdout only |
| `PUSHOVER_APP_TOKEN` | Optional | Pushover app token |
| `ALERT_SHARED_SECRET` | Recommended | Webhook auth header value |
| `VERIFY_TLS` | Optional | `true` (default) or `false` for self-signed UniFi certs |
| `DEFAULT_CAMERA_ID` | Optional | Fallback camera id when webhook payload has none |
| `SMART_DETECT_ONLY` | Optional | `true` = only use UniFi smart-detect types, skip AI label inference |
| `ANIMAL_SPECIES_FROM_SUMMARY` | Optional | `true` (default) — add species to animal alert title |
| `TITLE_ADD_PERSON_GENDER` | Optional | `true` (default) — add inferred gender to person alert title |
| `TITLE_ADD_VEHICLE_TYPE` | Optional | `true` (default) — add vehicle type to alert title |
| `TITLE_ADD_VEHICLE_MAKE_MODEL` | Optional | `false` (default) — add make/model if detected |
| `WEAPON_TITLE_HINT` | Optional | `true` (default) — add weapon type to title if detected |
| `PROTECT_TRIGGER_WEAPON` | Optional | Protect Alarm Manager trigger URL to fire on weapon detection |
| `PROTECT_TRIGGER_RACCOON` | Optional | Protect trigger URL to fire on after-hours raccoon detection |
| `ESCALATION_DEBOUNCE_SEC` | Optional | Seconds between repeated trigger fires (default 60) |

---

## Docker

```bash
# Build and run locally
docker build -t unifi-ai-alerts .
docker run --env-file .env -p 8080:8080 unifi-ai-alerts

# On Synology NAS (docker-compose.yaml targets /volume1/unifi-ai)
# Exposes port 18080 externally to avoid DSM conflicts
```

---

## API endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/unifi-webhook` | Main entry point — receives Protect alarm payload |
| `GET` | `/health` | Health check (`{"ok": true}`) |
| `GET` | `/debug/env` | Shows resolved env vars (no secret values) |
| `GET` | `/debug/cameramap` | Dumps camera id/MAC map from Protect |
| `GET` | `/debug/cameranames` | Shows id→name mappings |
| `GET` | `/debug/fetch?url=` | Tests image fetch with auth fallback chain |
| `GET` | `/debug/snapshot?camera_id=&ts_ms=` | Tests snapshot fetch |
| `POST` | `/debug/nameprobe` | Posts a webhook payload; returns camera resolution diagnostics |

---

## Key conventions

- **Image priority**: data URL in payload → URL thumbnail in payload → snapshot API fallback
- **Auth fallback chain**: unauthenticated → `X-API-KEY` (integration key) → `Bearer` token
- **Camera ID resolution**: 24-hex integration IDs preferred; MAC addresses resolved via camera map; ID→name cache refreshes every 60s
- **Label logic**: UniFi `smartDetectTypes` take priority over AI inference; `SMART_DETECT_ONLY=true` skips AI labeling entirely
- **Escalation triggers**: `fire_protect_trigger()` POSTs to a Protect Alarm Manager "Trigger Link" URL with debounce
- **`Archive/`**: historical versions of `main.py` — not imported, safe to ignore
- All modules are flat files (no package structure) — import as `from unifi import ...`
- The `ruff` linter is available as a dev dep: `ruff check .` / `ruff format .`
