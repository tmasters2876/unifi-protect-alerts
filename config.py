# config.py — shared env-var configuration for the split-out webhook/debug/escalation modules
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")

VERIFY_TLS = os.environ.get("VERIFY_TLS", "true").lower() == "true"
SHARED_SECRET = os.environ.get("ALERT_SHARED_SECRET", "")
DEFAULT_CAMERA_ID = os.environ.get("DEFAULT_CAMERA_ID")
PROTECT_HOST = (os.environ.get("PROTECT_HOST") or "").rstrip("/")
IKEY = os.environ.get("PROTECT_INTEGRATION_KEY") or ""
BTOKEN = os.environ.get("PROTECT_API_KEY") or ""  # optional; not required here

TRIGGER_WEAPON = os.environ.get("PROTECT_TRIGGER_WEAPON", "")
TRIGGER_RACCOON = os.environ.get("PROTECT_TRIGGER_RACCOON", "")
ESCALATION_DEBOUNCE_SEC = int(os.environ.get("ESCALATION_DEBOUNCE_SEC", "60"))
