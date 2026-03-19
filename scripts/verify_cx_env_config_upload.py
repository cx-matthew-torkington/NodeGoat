#!/usr/bin/env python3
import argparse
import json
import ssl
import urllib.parse
import urllib.request
from pathlib import Path


def load_cfg(path: Path) -> dict:
    out = {}
    for ln in path.read_text(encoding="utf-8").splitlines():
        s = ln.strip()
        if not s or s.startswith("#") or ":" not in s:
            continue
        k, v = s.split(":", 1)
        out[k.strip()] = v.strip().strip('"')
    return out


parser = argparse.ArgumentParser(description="Verify Checkmarx DAST environment config file upload")
parser.add_argument("--environment-name", default="MT_GinAndJuice", help="Environment domain/name")
parser.add_argument("--full", action="store_true", help="Print full environment JSON")
parser.add_argument("--list", action="store_true", help="List all environment domains and exit")
args = parser.parse_args()

cfg = load_cfg(Path.home() / ".checkmarx" / "checkmarxcli.yaml")
base = cfg["cx_base_uri"].rstrip("/")
auth = cfg["cx_base_auth_uri"].rstrip("/")
tenant = cfg["cx_tenant"]
apikey = cfg["cx_apikey"]

form = urllib.parse.urlencode(
    {
        "grant_type": "refresh_token",
        "client_id": "ast-app",
        "refresh_token": apikey,
    }
).encode("utf-8")
ctx = ssl._create_unverified_context()

req = urllib.request.Request(
    f"{auth}/auth/realms/{tenant}/protocol/openid-connect/token",
    data=form,
    method="POST",
    headers={"Content-Type": "application/x-www-form-urlencoded"},
)
token = json.loads(urllib.request.urlopen(req, context=ctx).read().decode("utf-8"))["access_token"]
headers = {"Accept": "*/*; version=1.0", "Authorization": f"Bearer {token}"}

req = urllib.request.Request(f"{base}/api/dast/scans/environments", headers=headers)
envs = json.loads(urllib.request.urlopen(req, context=ctx).read().decode("utf-8")).get("environments", [])

if args.list:
    for e in envs:
        print(f"{e.get('domain')}\t{e.get('environmentId')}")
    raise SystemExit(0)

env = next((e for e in envs if e.get("domain") == args.environment_name), None)
if not env:
    print(json.dumps({"found": False, "domain": args.environment_name}, indent=2))
    raise SystemExit(0)

env_id = env["environmentId"]
req = urllib.request.Request(f"{base}/api/dast/scans/environment/{env_id}", headers=headers)
detail = json.loads(urllib.request.urlopen(req, context=ctx).read().decode("utf-8"))
config = ((detail.get("settings") or {}).get("configFileSettings") or {})
scan_config = detail.get("scanConfig") or {}
auth_method = detail.get("authMethod")

print(
    json.dumps(
        {
            "found": True,
            "environmentId": env_id,
            "domain": detail.get("domain"),
            "hasAuth": detail.get("hasAuth"),
            "isPublic": detail.get("isPublic"),
            "configFileName": config.get("name"),
            "configContentLength": len(config.get("content", "") or ""),
            "hasConfig": bool(config.get("name") and config.get("content")),
            "configApplied": bool(auth_method == "CONFIG" and scan_config.get("ScanURL")),
            "authMethod": auth_method,
            "scanUrl": scan_config.get("ScanURL"),
            "includePathsCount": len(scan_config.get("IncludePaths") or []),
        },
        indent=2,
    )
)

if args.full:
    print(json.dumps(detail, indent=2))
