#!/usr/bin/env python3
import os
import json
import hmac
import hashlib
import urllib.request
import urllib.error
from datetime import datetime, timezone

B12_ENDPOINT = "https://b12.io/apply/submission"

def iso8601_utc_now() -> str:
    # ISO 8601 with milliseconds and Z
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

def canonical_json_bytes(payload: dict) -> bytes:
    # Keys sorted, no extra whitespace, UTF-8 encoded
    s = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return s.encode("utf-8")

def hmac_sha256_hex(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()

def required_env(name: str) -> str:
    v = os.getenv(name)
    if not v:
        raise SystemExit(f"Missing required environment variable: {name}")
    return v

def build_links_from_github_env() -> tuple[str, str]:
    # GitHub provides these automatically in Actions
    server_url = required_env("GITHUB_SERVER_URL")          # e.g. https://github.com
    repo = required_env("GITHUB_REPOSITORY")                # e.g. username/reponame
    run_id = required_env("GITHUB_RUN_ID")                  # e.g. 1234567890

    repository_link = f"{server_url}/{repo}"
    action_run_link = f"{server_url}/{repo}/actions/runs/{run_id}"
    return repository_link, action_run_link

def main() -> None:
    name = required_env("B12_NAME")
    email = required_env("B12_EMAIL")
    resume_link = required_env("B12_RESUME_LINK")

    repository_link, action_run_link = build_links_from_github_env()

    payload = {
        "timestamp": iso8601_utc_now(),
        "name": name,
        "email": email,
        "resume_link": resume_link,
        "repository_link": repository_link,
        "action_run_link": action_run_link,
    }

    body = canonical_json_bytes(payload)

    signing_secret = os.getenv("B12_SIGNING_SECRET", "hello-there-from-b12").encode("utf-8")
    digest = hmac_sha256_hex(signing_secret, body)

    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "X-Signature-256": f"sha256={digest}",
        "User-Agent": "b12-application-script/1.0",
    }

    req = urllib.request.Request(
        B12_ENDPOINT,
        data=body,
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_body = resp.read().decode("utf-8")
            if resp.status != 200:
                raise SystemExit(f"Non-200 response: {resp.status} body={resp_body}")

    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        raise SystemExit(f"HTTPError: {e.code} body={err_body}") from e
    except Exception as e:
        raise SystemExit(f"Request failed: {e}") from e

    try:
        data = json.loads(resp_body)
    except json.JSONDecodeError:
        raise SystemExit(f"Invalid JSON response: {resp_body}")

    if not (isinstance(data, dict) and data.get("success") is True and "receipt" in data):
        raise SystemExit(f"Unexpected response: {resp_body}")

    # This is what B12 wants you to copy/paste into the application form
    print(data["receipt"])

if __name__ == "__main__":
    main()
