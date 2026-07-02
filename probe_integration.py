# probe_integration.py — stdlib-only; dumps camera id + every MAC-like string found per camera
import os, ssl, json, re, urllib.request
from pathlib import Path

def load_dotenv_simple():
    env_path = Path(__file__).resolve().parent / ".env"
    if env_path.exists():
        for raw in env_path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())


load_dotenv_simple()

HOST = (os.environ.get("PROTECT_HOST") or "").rstrip("/")
IKEY = os.environ.get("PROTECT_INTEGRATION_KEY") or ""
VERIFY_TLS = (os.environ.get("VERIFY_TLS", "true").lower() == "true")

if not HOST or not IKEY:
    raise SystemExit("Set PROTECT_HOST and PROTECT_INTEGRATION_KEY in .env before running this probe.")

ctx = None if VERIFY_TLS else ssl._create_unverified_context()
req = urllib.request.Request(
    f"{HOST}/proxy/protect/integration/v1/cameras",
    headers={"X-API-KEY": IKEY}
)
with urllib.request.urlopen(req, context=ctx) as r:
    cams = json.load(r)

print("Integration cameras:", len(cams))
macre = re.compile(r"[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}")
for cam in cams:
    cid = cam.get("id")
    macs = set()
    # common fields
    for k in ("mac", "macAddress", "MacAddress", "deviceMac"):
        v = cam.get(k)
        if isinstance(v, str):
            macs.add(v)

    # deep scan any MAC-like strings
    def dfs(o):
        if isinstance(o, dict):
            for v in o.values():
                dfs(v)
        elif isinstance(o, list):
            for v in o:
                dfs(v)
        elif isinstance(o, str):
            s = o.replace("-", ":")
            m = macre.search(s)
            if m:
                macs.add(m.group(0))

    dfs(cam)
    print(cid, sorted(macs))
