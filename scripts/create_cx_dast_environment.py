#!/usr/bin/env python3
"""Create or update a Checkmarx One DAST environment using a named config file.

This script uses the Checkmarx DAST Scans Service API:
- POST /api/dast/scans/environment
- PUT  /api/dast/scans/environment

It reads defaults from ~/.checkmarx/checkmarxcli.yaml when not explicitly provided.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional


DEFAULT_CONFIG = Path.home() / ".checkmarx" / "checkmarxcli.yaml"
DEFAULT_CLIENT_ID = "ast-app"
LOG_FILE = Path("cx_dast_environment.log")


def _log(message: str) -> None:
    """Append a timestamped message to the log file."""
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    entry = f"[{ts}] {message}\n"
    with LOG_FILE.open("a", encoding="utf-8") as fh:
        fh.write(entry)


def parse_kv_yaml(path: Path) -> Dict[str, str]:
    """Parse simple 'key: value' lines from the CLI yaml file.

    The Checkmarx CLI config is flat enough for this lightweight parser and avoids
    requiring external dependencies.
    """
    out: Dict[str, str] = {}
    if not path.exists():
        return out

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        out[key.strip()] = value.strip().strip('"')
    return out


def resolve_setting(
    arg_value: Optional[str],
    env_keys: List[str],
    cfg: Dict[str, str],
    cfg_keys: List[str],
) -> Optional[str]:
    if arg_value:
        return arg_value
    for key in env_keys:
        val = os.getenv(key)
        if val:
            return val
    for key in cfg_keys:
        val = cfg.get(key)
        if val:
            return val
    return None


def http_request(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[bytes] = None,
    insecure: bool = False,
    verbose: bool = False,
) -> tuple[int, str]:
    req = urllib.request.Request(url=url, data=body, method=method)
    for k, v in headers.items():
        req.add_header(k, v)

    if verbose:
        # Print a curl-equivalent command so the exact request is visible
        safe_headers = {
            k: ("<token>" if k.lower() == "authorization" else v)
            for k, v in headers.items()
        }
        header_flags = " ".join(f"-H '{k}: {v}'" for k, v in safe_headers.items())
        insecure_flag = " -k" if insecure else ""
        if body:
            body_str = body.decode("utf-8", errors="replace")
            # Pretty-print JSON bodies
            try:
                body_str = json.dumps(json.loads(body_str), indent=2)
            except (json.JSONDecodeError, ValueError):
                pass
            print(f"\n--- REQUEST ---\ncurl -X {method}{insecure_flag} '{url}' \\\n  {header_flags} \\\n  -d '{body_str}'\n", file=sys.stderr)
        else:
            print(f"\n--- REQUEST ---\ncurl -X {method}{insecure_flag} '{url}' \\\n  {header_flags}\n", file=sys.stderr)

    # Always log every request to the log file
    safe_headers_log = {
        k: ("<token>" if k.lower() == "authorization" else v)
        for k, v in headers.items()
    }
    body_log = ""
    if body:
        body_decoded = body.decode("utf-8", errors="replace")
        try:
            body_log = json.dumps(json.loads(body_decoded))
        except (json.JSONDecodeError, ValueError):
            body_log = body_decoded[:500]
    _log(f"REQUEST  {method} {url} headers={json.dumps(safe_headers_log)} body={body_log}")

    try:
        context = None
        if insecure:
            context = ssl._create_unverified_context()
        with urllib.request.urlopen(req, timeout=30, context=context) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            _log(f"RESPONSE {method} {url} status={resp.getcode()} body={text[:300]}")
            return resp.getcode(), text
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", errors="replace")
        _log(f"RESPONSE {method} {url} status={exc.code} body={text[:300]}")
        return exc.code, text


def get_access_token(
    base_auth_uri: str, tenant: str, client_id: str, api_key: str, insecure: bool
) -> str:
    token_url = f"{base_auth_uri.rstrip('/')}/auth/realms/{tenant}/protocol/openid-connect/token"
    form = urllib.parse.urlencode(
        {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": api_key,
        }
    ).encode("utf-8")

    code, body = http_request(
        "POST",
        token_url,
        {"Content-Type": "application/x-www-form-urlencoded"},
        form,
        insecure=insecure,
    )
    if code != 200:
        raise RuntimeError(f"Token request failed ({code}): {body}")

    payload = json.loads(body)
    token = payload.get("access_token")
    if not token:
        raise RuntimeError("Token response did not contain access_token")
    return token


def list_environments(base_uri: str, token: str, insecure: bool) -> List[Dict[str, Any]]:
    url = f"{base_uri.rstrip('/')}/api/dast/scans/environments"
    code, body = http_request(
        "GET",
        url,
        {
            "Accept": "*/*; version=1.0",
            "Authorization": f"Bearer {token}",
        },
        insecure=insecure,
    )
    if code != 200:
        raise RuntimeError(f"List environments failed ({code}): {body}")

    payload = json.loads(body)
    return payload.get("environments", [])


def get_environment(base_uri: str, token: str, environment_id: str, insecure: bool) -> Dict[str, Any]:
    url = f"{base_uri.rstrip('/')}/api/dast/scans/environment/{environment_id}"
    code, body = http_request(
        "GET",
        url,
        {
            "Accept": "*/*; version=1.0",
            "Authorization": f"Bearer {token}",
        },
        insecure=insecure,
    )
    if code != 200:
        raise RuntimeError(f"Retrieve environment failed ({code}): {body}")
    return json.loads(body)


def build_payload(
    args: argparse.Namespace,
    config_name: str,
    config_content: str,
) -> Dict[str, Any]:
    """Build the environment create/update payload.

    configFileSettings is the documented mechanism for supplying a ZAP/auth
    config file.  The API stores the content internally and the scan engine
    processes it on the first run, populating authMethod and scanConfig
    afterward.  The raw content is NOT returned by GET /environment/{id} —
    that is expected behaviour, not a sign the upload failed.
    """
    payload: Dict[str, Any] = {
        "domain": args.environment_name,
        "url": args.target_url,
        "scanType": args.scan_type,
        "isPublic": args.is_public,
        "hasAuth": args.has_auth,
        "settings": {
            "configFileSettings": {
                "name": config_name,
                "content": config_content,
            }
        },
    }

    if args.project_ids:
        payload["projectIds"] = args.project_ids
    if args.tags:
        payload["tags"] = args.tags
    if args.groups:
        payload["groups"] = args.groups

    return payload


def create_or_update_environment(
    base_uri: str,
    token: str,
    payload: Dict[str, Any],
    existing_env_id: Optional[str],
    create_only: bool,
    insecure: bool,
    verbose: bool = False,
) -> Dict[str, Any]:
    url = f"{base_uri.rstrip('/')}/api/dast/scans/environment"
    headers = {
        "Accept": "*/*; version=1.0",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }

    if existing_env_id and not create_only:
        payload = dict(payload)
        payload["environmentId"] = existing_env_id
        code, body = http_request(
            "PUT", url, headers, json.dumps(payload).encode("utf-8"), insecure=insecure, verbose=verbose
        )
        if code not in (200, 201):
            raise RuntimeError(f"Update environment failed ({code}): {body}")
        return {
            "action": "updated",
            "environmentId": existing_env_id,
            "response": body,
        }

    code, body = http_request(
        "POST", url, headers, json.dumps(payload).encode("utf-8"), insecure=insecure, verbose=verbose
    )
    if code not in (200, 201):
        raise RuntimeError(f"Create environment failed ({code}): {body}")

    created_id = body.strip().strip('"')
    return {
        "action": "created",
        "environmentId": created_id,
        "response": body,
    }


def _extract_yaml_scalar(text: str, key: str) -> str:
    match = re.search(rf"^\s*{re.escape(key)}\s*:\s*\"?([^\"\n]+)\"?\s*$", text, re.MULTILINE)
    return match.group(1).strip() if match else ""


def _extract_yaml_list(text: str, key: str) -> List[str]:
    lines = text.splitlines()
    out: List[str] = []
    start_idx = -1
    base_indent = 0
    for i, line in enumerate(lines):
        if re.match(rf"^\s*{re.escape(key)}\s*:\s*$", line):
            start_idx = i + 1
            base_indent = len(line) - len(line.lstrip(" "))
            break
    if start_idx < 0:
        return out

    for line in lines[start_idx:]:
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= base_indent:
            break
        m = re.match(r"^\s*-\s*\"?([^\"\n]+)\"?\s*$", line)
        if m:
            out.append(m.group(1).strip())
    return out


def build_scan_config_from_zap_yaml(args: argparse.Namespace, yaml_text: str) -> Dict[str, Any]:
    include_paths = _extract_yaml_list(yaml_text, "includePaths")
    login_page = _extract_yaml_scalar(yaml_text, "loginPageUrl")
    login_body = _extract_yaml_scalar(yaml_text, "loginRequestBody")
    logged_in = _extract_yaml_scalar(yaml_text, "loggedInRegex")
    logged_out = _extract_yaml_scalar(yaml_text, "loggedOutRegex")
    session_method = _extract_yaml_scalar(yaml_text, "method") or "cookie"

    credentials_user = args.user_name
    credentials_password = args.user_password

    return {
        "ScanURL": args.target_url.rstrip("/"),
        "IncludePaths": include_paths,
        "Authentication": {
            "Method": "form",
            "Parameters": {
                "Script": "",
                "ScriptEngine": "",
                "BrowserID": "",
                "LoginPageURL": login_page,
                "LoginPageWait": 0,
                "Steps": None,
                "StepDelay": 0,
                "MinWaitFor": 0,
            },
            "Verification": {
                "Method": "response",
                "LoggedInRegex": logged_in,
                "LoggedOutRegex": logged_out,
                "PollFrequency": 60,
                "PollUnits": "seconds",
                "PollURL": "",
                "PollPostData": "",
                "PollAdditionalHeaders": None,
            },
        },
        "SessionManagement": {
            "Method": session_method,
            "Parameters": None,
        },
        "Users": [
            {
                "Name": args.user_name,
                "Credentials": {
                    "Username": credentials_user,
                    "Password": credentials_password,
                },
            }
        ],
    }


def apply_scan_config_fallback(
    base_uri: str,
    token: str,
    args: argparse.Namespace,
    environment_id: str,
    config_name: str,
    config_content: str,
    insecure: bool,
) -> None:
    scan_config = build_scan_config_from_zap_yaml(args, config_content)
    payload: Dict[str, Any] = {
        "environmentId": environment_id,
        "domain": args.environment_name,
        "url": args.target_url,
        "scanType": args.scan_type,
        "isPublic": args.is_public,
        "hasAuth": args.has_auth,
        "scanConfig": scan_config,
        "settings": {
            "configFileSettings": {
                "name": config_name,
                "content": config_content,
            }
        },
    }
    if args.project_ids:
        payload["projectIds"] = args.project_ids
    if args.tags:
        payload["tags"] = args.tags
    if args.groups:
        payload["groups"] = args.groups

    url = f"{base_uri.rstrip('/')}/api/dast/scans/environment"
    code, body = http_request(
        "PUT",
        url,
        {
            "Accept": "*/*; version=1.0",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        json.dumps(payload).encode("utf-8"),
        insecure=insecure,
    )
    if code not in (200, 201):
        raise RuntimeError(f"Fallback apply scanConfig failed ({code}): {body}")


def run_scan(base_uri: str, token: str, environment_id: str, scan_type: str, insecure: bool) -> Dict[str, Any]:
    """Trigger a DAST scan for the given environment and return the scan details."""
    url = f"{base_uri.rstrip('/')}/api/dast/scans/scan"
    payload = {
        "ScanType": scan_type,
        "EnvironmentID": environment_id,
    }
    code, body = http_request(
        "POST",
        url,
        {
            "Accept": "*/*; version=1.0",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        json.dumps(payload).encode("utf-8"),
        insecure=insecure,
    )
    if code not in (200, 201):
        raise RuntimeError(f"Run scan failed ({code}): {body}")
    return json.loads(body)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create or update a Checkmarx One DAST environment from a named config file"
    )
    parser.add_argument("--environment-name", required=True, help="Environment domain/name in Checkmarx")
    parser.add_argument("--target-url", required=True, help="Target URL to scan (e.g. https://ginandjuice.shop)")
    parser.add_argument("--scan-type", default="DAST", choices=["DAST", "DASTAPI"], help="DAST scan type")
    parser.add_argument("--config-file", required=True, help="Path to config file content to upload")
    parser.add_argument("--config-name", help="Logical config file name stored in environment settings")
    parser.add_argument("--project-id", dest="project_ids", action="append", help="Project ID to link")
    parser.add_argument("--tag", dest="tags", action="append", help="Tag to assign (repeatable)")
    parser.add_argument("--group", dest="groups", action="append", help="Group to assign (repeatable)")
    parser.add_argument("--is-public", action="store_true", help="Create environment as public")
    parser.add_argument("--has-auth", action="store_true", default=True, help="Mark environment as authenticated")
    parser.add_argument("--no-auth", dest="has_auth", action="store_false", help="Disable auth flag")
    parser.add_argument("--create-only", action="store_true", help="Fail if environment already exists")
    parser.add_argument("--run-scan", action="store_true", help="Trigger a DAST scan immediately after the environment is created or updated")
    parser.add_argument("--verbose", action="store_true", help="Print the curl-equivalent HTTP request to stderr before sending")
    parser.add_argument("--user-name", default="carlos", help="Auth user name for scanConfig fallback")
    parser.add_argument("--user-password", default="hunter2", help="Auth password for scanConfig fallback")

    parser.add_argument("--base-uri", help="Checkmarx base URI")
    parser.add_argument("--base-auth-uri", help="Checkmarx IAM base auth URI")
    parser.add_argument("--tenant", help="Checkmarx tenant")
    parser.add_argument("--api-key", help="Checkmarx API key (refresh token)")
    parser.add_argument("--client-id", default=DEFAULT_CLIENT_ID, help="OAuth client id (default: ast-app)")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS certificate validation")
    parser.add_argument(
        "--cx-config",
        default=str(DEFAULT_CONFIG),
        help="Path to checkmarxcli.yaml for defaults",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    config_path = Path(args.config_file)
    if not config_path.exists():
        print(f"ERROR: config file not found: {config_path}", file=sys.stderr)
        return 2

    cfg = parse_kv_yaml(Path(args.cx_config))

    base_uri = resolve_setting(args.base_uri, ["CX_BASE_URI", "cx_base_uri"], cfg, ["cx_base_uri"])
    base_auth_uri = resolve_setting(
        args.base_auth_uri,
        ["CX_BASE_AUTH_URI", "cx_base_auth_uri"],
        cfg,
        ["cx_base_auth_uri"],
    )
    tenant = resolve_setting(args.tenant, ["CX_TENANT", "cx_tenant"], cfg, ["cx_tenant"])
    api_key = resolve_setting(args.api_key, ["CX_APIKEY", "cx_apikey"], cfg, ["cx_apikey"])

    missing = []
    if not base_uri:
        missing.append("base_uri")
    if not base_auth_uri:
        missing.append("base_auth_uri")
    if not tenant:
        missing.append("tenant")
    if not api_key:
        missing.append("api_key")
    if missing:
        print(f"ERROR: missing required settings: {', '.join(missing)}", file=sys.stderr)
        return 2

    config_name = args.config_name or config_path.name
    config_content = config_path.read_text(encoding="utf-8")

    _log(f"START environment-name={args.environment_name!r} target-url={args.target_url!r} scan-type={args.scan_type!r} config-file={args.config_file!r} run-scan={args.run_scan}")

    try:
        token = get_access_token(base_auth_uri, tenant, args.client_id, api_key, args.insecure)
        environments = list_environments(base_uri, token, args.insecure)
        existing = next((e for e in environments if e.get("domain") == args.environment_name), None)

        if existing and args.create_only:
            raise RuntimeError(
                f"Environment '{args.environment_name}' already exists with id {existing.get('environmentId')}"
            )

        payload = build_payload(args, config_name, config_content)
        result = create_or_update_environment(
            base_uri=base_uri,
            token=token,
            payload=payload,
            existing_env_id=existing.get("environmentId") if existing else None,
            create_only=args.create_only,
            insecure=args.insecure,
            verbose=args.verbose,
        )

        # Verify the environment exists and has the expected basic settings.
        # NOTE: authMethod and scanConfig are populated by the Checkmarx scan
        # engine after the first scan run.  They will be empty for a newly
        # configured environment — that is expected, not a failure.
        verification = get_environment(
            base_uri=base_uri,
            token=token,
            environment_id=result["environmentId"],
            insecure=args.insecure,
        )
        verified_scan_config = verification.get("scanConfig") or {}
        auth_method = verification.get("authMethod") or ""
        configured_scan_url = verified_scan_config.get("ScanURL")
        # authMethod is only "CONFIG" after a successful authenticated scan.
        auth_verified = bool(auth_method == "CONFIG" and configured_scan_url)

        output: Dict[str, Any] = {
            "ok": True,
            "action": result["action"],
            "environmentName": args.environment_name,
            "environmentId": result["environmentId"],
            "targetUrl": args.target_url,
            "scanType": args.scan_type,
            "configFileName": config_name,
            "configFileSubmitted": True,
            "hasAuth": verification.get("hasAuth"),
            "authVerified": auth_verified,
            "authMethod": auth_method or None,
            "note": (
                "Config file submitted. authMethod and scanConfig will be"
                " visible after the first scan run."
                if not auth_verified
                else "Config applied and authentication already verified."
            ),
        }

        if args.run_scan:
            scan_result = run_scan(
                base_uri=base_uri,
                token=token,
                environment_id=result["environmentId"],
                scan_type=args.scan_type,
                insecure=args.insecure,
            )
            output["scan"] = scan_result

        _log(f"DONE action={result['action']!r} environmentId={result['environmentId']!r} authVerified={auth_verified} run-scan={args.run_scan}")
        print(json.dumps(output, indent=2))
        return 0
    except Exception as exc:
        _log(f"ERROR {exc}")
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
