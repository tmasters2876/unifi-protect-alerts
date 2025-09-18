# probe_unvr.py  — stdlib-only (no httpx needed)
import os, re, time, json, ssl
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

# --- tiny .env loader (no external deps) ---
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

HOST   = (os.environ.get("PROTECT_HOST") or "").rstrip("/")
IKEY   = os.environ.get("PROTECT_INTEGRATION_KEY") or ""
BTOKEN = os.environ.get("PROTECT_API_KEY") or ""
VERIFY = (os.environ.get("VERIFY_TLS","true").lower() == "true")

CTX = None if VERIFY else ssl._create_unverified_context()

def _req(url: str, headers=None, params=None, accept: str | None = None):
    if params:
        qs = urlencode(params)
        url = url + ("&" if "?" in url else "?") + qs
    headers = dict(headers or {})
    if accept:
        headers["Accept"] = accept
    req = Request(url, headers=headers, method="GET")
    try:
        with urlopen(req, context=CTX) as r:
            ctype = r.headers.get("content-type","")
            return r.status, ctype, r.read()
    except HTTPError as e:
        ctype = e.headers.get("content-type","") if e.headers else ""
        return e.code, ctype, e.read()
    except URLError as e:
        return 0, "", str(e).encode()

def _get_json(url: str, headers=None, params=None):
    status, ctype, data = _req(url, headers=headers, params=params, accept="application/json")
    if status != 200:
        raise RuntimeError(f"HTTP {status} at {url}: {data[:200]!r}")
    try:
        return json.loads(data.decode("utf-8", "ignore"))
    except Exception as e:
        raise RuntimeError(f"Bad JSON at {url}: {e}; first bytes={data[:120]!r}")

def norm_mac(s: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", (s or "")).upper()

def get_integration_cameras():
    if not IKEY:
        return []
    url = f"{HOST}/proxy/protect/integration/v1/cameras"
    return _get_json(url, headers={"X-API-KEY": IKEY})

def get_bootstrap():
    if not BTOKEN:
        return {}
    url = f"{HOST}/proxy/protect/api/bootstrap"
    return _get_json(url, headers={"Authorization": f"Bearer {BTOKEN}"})

def try_snapshot(cam_id: str):
    ts = int(time.time() * 1000)
    tried = []

    if IKEY:
        for pn in ("timestamp","ts"):
            url = f"{HOST}/proxy/protect/integration/v1/cameras/{cam_id}/snapshot"
            st, ctype, body = _req(url, headers={"X-API-KEY": IKEY},
                                   params={pn: str(ts)}, accept="image/*")
            tried.append(("integration", pn, st, ctype, len(body)))
            if st == 200 and ctype.lower().startswith("image/"):
                return ("integration", pn, len(body), ctype)

    if BTOKEN:
        url = f"{HOST}/proxy/protect/api/cameras/{cam_id}/snapshot"
        st, ctype, body = _req(url, headers={"Authorization": f"Bearer {BTOKEN}"},
                               params={"ts": str(ts), "force": "true"}, accept="image/*")
        tried.append(("classic", "ts", st, ctype, len(body)))
        if st == 200 and ctype.lower().startswith("image/"):
            return ("classic", "ts", len(body), ctype)

    return ("failed", tried, None, None)

def main():
    if not HOST:
        print("❌ PROTECT_HOST missing in .env"); return
    print(f"Host: {HOST}  VERIFY_TLS={VERIFY}  has IKEY={bool(IKEY)}  has PAT={bool(BTOKEN)}")

    id_to_name: dict[str,str] = {}
    mac_to_name: dict[str,str] = {}

    # 1) Integration cameras
    try:
        cams = get_integration_cameras()
        print(f"Integration cameras: {len(cams)}")
        for c in cams:
            cid = c.get("id")
            nm  = (c.get("name") or c.get("displayName") or c.get("channelName") or "").strip()
            mac = (c.get("mac") or c.get("macAddress") or "").strip()
            if cid and nm:
                id_to_name[cid] = nm
            if mac and nm:
                mac_to_name[norm_mac(mac)] = nm
            print(f"  - id={cid}  name={nm}  mac={mac}")
    except Exception as e:
        print(f"Integration /cameras failed: {e}")

    # 2) Classic bootstrap
    try:
        bs = get_bootstrap()
        cams = bs.get("cameras", []) if isinstance(bs, dict) else []
        print(f"Bootstrap cameras: {len(cams)}")
        for c in cams:
            cid = c.get("id")
            nm  = (c.get("name") or c.get("displayName") or "").strip()
            mac = (c.get("mac") or "").strip()
            if cid and nm:
                id_to_name.setdefault(cid, nm)
            if mac and nm:
                mac_to_name.setdefault(norm_mac(mac), nm)
            print(f"  - id={cid}  name={nm}  mac={mac}")
    except Exception as e:
        print(f"Classic /bootstrap failed: {e}")

    print("\nID→Name entries:", len(id_to_name))
    print("MAC→Name entries:", len(mac_to_name))

    # 3) Snapshot test (pick first id we know)
    sample_id = next(iter(id_to_name.keys()), None)
    if sample_id:
        print(f"\nTrying snapshot for id={sample_id} …")
        mode, info, size, ctype = try_snapshot(sample_id)
        if mode != "failed":
            print(f"✅ Snapshot via {mode} ({info})  bytes={size}  content-type={ctype}")
        else:
            print("❌ Snapshot failed. Tried:")
            for row in info:
                print("   ", row)
    else:
        print("\n(no camera id available to test snapshot)")

    Path("id_to_name.json").write_text(json.dumps(id_to_name, indent=2))
    Path("mac_to_name.json").write_text(json.dumps(mac_to_name, indent=2))
    print("\nWrote id_to_name.json and mac_to_name.json")

if __name__ == "__main__":
    main()
