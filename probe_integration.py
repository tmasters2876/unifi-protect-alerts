import ssl, json, urllib.request, re

HOST = "https://192.168.200.43"  # your NVR
IKEY = "N_SI47lOy0QWMEcwWtaFEIMIABCpeHrN"  # your integration key

ctx  = ssl._create_unverified_context()
req  = urllib.request.Request(
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
    for k in ("mac","macAddress","MacAddress","deviceMac"):
        v = cam.get(k)
        if isinstance(v,str):
            macs.add(v)
    # deep scan any MAC-like strings
    def dfs(o):
        if isinstance(o,dict):
            for v in o.values(): dfs(v)
        elif isinstance(o,list):
            for v in o: dfs(v)
        elif isinstance(o,str):
            s = o.replace("-",":")
            m = macre.search(s)
            if m: macs.add(m.group(0))
    dfs(cam)
    print(cid, sorted(macs))
