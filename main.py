# main.py — FastAPI app: logging setup + route registration (logic lives in webhook.py/debug_routes.py)
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from fastapi import FastAPI

import config  # noqa: F401 (loads .env before any other module reads os.environ)
import debug_routes
import webhook

LOG = logging.getLogger("uvicorn.error")

# Persist logs to disk (docker-compose mounts ./logs on the NAS) in addition to stdout.
_LOG_DIR = Path(__file__).resolve().parent / "logs"
try:
    _LOG_DIR.mkdir(exist_ok=True)
    _file_handler = RotatingFileHandler(_LOG_DIR / "app.log", maxBytes=5_000_000, backupCount=3)
    _file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    LOG.addHandler(_file_handler)
except OSError as e:
    LOG.warning(f"[LOGGING] could not set up file logging: {e}")

app = FastAPI(title="UniFi AI Alerts")
app.include_router(debug_routes.router)
app.include_router(webhook.router)
