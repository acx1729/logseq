#!/usr/bin/env python3
"""Prepare per-case CLI config for sync e2e tests."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

DEFAULT_OAUTH_CLIENT_ID = "logseq-sync"


def fail(message: str, **context: object) -> None:
    payload = {"status": "error", "message": message}
    if context:
        payload["context"] = context
    print(json.dumps(payload), file=sys.stderr)
    raise SystemExit(1)


def read_auth(auth_path: Path) -> dict:
    if not auth_path.exists():
        fail("sync auth file is missing", auth_path=str(auth_path), hint="Run `logseq login` first.")
    try:
        payload = json.loads(auth_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        fail("sync auth file is invalid JSON", auth_path=str(auth_path), detail=str(error))

    has_token = any(payload.get(key) for key in ("refresh-token", "id-token", "access-token"))
    if not has_token:
        fail(
            "sync auth file does not contain usable tokens",
            auth_path=str(auth_path),
            required_any_of=["refresh-token", "id-token", "access-token"],
        )
    return payload


def write_config(
    output_path: Path,
    http_base: str,
    ws_url: str,
    oauth_token_endpoint: str,
    oauth_authorize_endpoint: str,
    oauth_client_id: str,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = "\n".join(
        [
            "{",
            " :output-format :json",
            f' :http-base "{http_base}"',
            f' :ws-url "{ws_url}"',
            f' :oauth-token-endpoint "{oauth_token_endpoint}"',
            f' :oauth-authorize-endpoint "{oauth_authorize_endpoint}"',
            f' :oauth-client-id "{oauth_client_id}"',
            "}",
            "",
        ]
    )
    output_path.write_text(payload, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare cli.edn for sync e2e")
    parser.add_argument("--output", required=True)
    parser.add_argument("--auth-path", default="~/logseq/auth.json")
    parser.add_argument("--http-base", required=True)
    parser.add_argument("--ws-url", required=True)
    parser.add_argument("--oauth-token-endpoint", help="default: <http-base>/auth/token")
    parser.add_argument("--oauth-authorize-endpoint", help="default: <http-base>/auth/siwe/start")
    parser.add_argument("--oauth-client-id", default=DEFAULT_OAUTH_CLIENT_ID)
    args = parser.parse_args()

    auth_path = Path(args.auth_path).expanduser().resolve()
    _auth = read_auth(auth_path)

    http_base = args.http_base.rstrip("/")
    oauth_token_endpoint = args.oauth_token_endpoint or f"{http_base}/auth/token"
    oauth_authorize_endpoint = args.oauth_authorize_endpoint or f"{http_base}/auth/siwe/start"

    output_path = Path(args.output).expanduser().resolve()
    write_config(output_path, args.http_base, args.ws_url, oauth_token_endpoint, oauth_authorize_endpoint, args.oauth_client_id)

    print(
        json.dumps(
            {
                "status": "ok",
                "auth_path": str(auth_path),
                "config_path": str(output_path),
                "http_base": args.http_base,
                "ws_url": args.ws_url,
                "oauth_token_endpoint": oauth_token_endpoint,
                "oauth_authorize_endpoint": oauth_authorize_endpoint,
                "oauth_client_id": args.oauth_client_id,
            }
        )
    )


if __name__ == "__main__":
    main()
