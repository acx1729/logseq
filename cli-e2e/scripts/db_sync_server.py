#!/usr/bin/env python3
"""Manage local db-sync server process for cli-e2e sync suite."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_TOKEN_AUDIENCE = "logseq-sync"


def fail(message: str, **context: object) -> None:
    payload = {"status": "error", "message": message}
    if context:
        payload["context"] = context
    print(json.dumps(payload), file=sys.stderr)
    raise SystemExit(1)


def load_pid(pid_file: Path) -> Optional[int]:
    if not pid_file.exists():
        return None
    raw = pid_file.read_text(encoding="utf-8").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def process_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        kernel32 = ctypes.windll.kernel32
        access = 0x00100000 | 0x1000  # SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION
        handle = kernel32.OpenProcess(access, False, pid)
        if handle:
            kernel32.CloseHandle(handle)
            return True
        return ctypes.get_last_error() == 5
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    else:
        return True


def terminate_process(pid: int, force: bool) -> bool:
    if pid <= 0:
        return True
    if os.name == "nt":
        cmd = ["taskkill", "/PID", str(pid), "/T"]
        if force:
            cmd.append("/F")
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        return result.returncode == 0 or not process_running(pid)
    try:
        os.kill(pid, signal.SIGKILL if force else signal.SIGTERM)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return True


def require_auth_file(path: Path) -> None:
    if not path.exists():
        fail("sync auth file is missing", auth_path=str(path), hint="Run `logseq login` against this server, or pass --mint-auth.")


# Helper scripts live in this checkout, next to this launcher, regardless of --repo-root.
SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "deps" / "db-sync" / "scripts"


def run_node_script(repo_root: Path, script: str, args: list, env: Dict[str, str]) -> Dict[str, Any]:
    script_path = SCRIPTS_DIR / script
    result = subprocess.run(
        ["node", str(script_path), *args],
        cwd=str(repo_root),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        fail(f"{script} failed", detail=result.stderr.strip() or result.stdout.strip())
    last_line = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else "{}"
    try:
        return json.loads(last_line)
    except json.JSONDecodeError:
        return {"raw": last_line}


def wait_health(base_url: str, timeout_s: float, interval_s: float) -> bool:
    deadline = time.time() + timeout_s
    url = base_url.rstrip("/") + "/health"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    while time.time() < deadline:
        try:
            with opener.open(url, timeout=2) as response:
                if response.status == 200:
                    return True
        except (urllib.error.URLError, TimeoutError, socket.timeout):
            pass
        time.sleep(interval_s)
    return False


def add_node_path(env: Dict[str, str], path: Path) -> None:
    existing = env.get("NODE_PATH")
    next_path = str(path)
    env["NODE_PATH"] = next_path if not existing else next_path + os.pathsep + existing


def start_server(args: argparse.Namespace) -> None:
    repo_root = Path(args.repo_root).expanduser().resolve()
    entry = repo_root / "deps" / "db-sync" / "worker" / "dist" / "node-adapter.js"
    if not entry.exists():
        fail("db-sync node adapter build artifact is missing", entry=str(entry), hint="Run: yarn --cwd deps/db-sync build:node-adapter")

    pid_file = Path(args.pid_file).expanduser().resolve()
    log_file = Path(args.log_file).expanduser().resolve()
    data_dir = Path(args.data_dir).expanduser().resolve()

    pid_file.parent.mkdir(parents=True, exist_ok=True)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    existing_pid = load_pid(pid_file)
    if existing_pid and process_running(existing_pid):
        fail("db-sync server already running", pid=existing_pid, pid_file=str(pid_file))

    auth_path = Path(args.auth_path).expanduser().resolve() if args.auth_path else None
    if auth_path and not args.mint_auth:
        require_auth_file(auth_path)

    env = os.environ.copy()
    add_node_path(env, repo_root / "deps" / "db-sync" / "node_modules")

    # The local server signs its own tokens with a development key file; the
    # same key can mint tokens offline (see deps/db-sync/scripts/mint-token.mjs).
    signing_key_file = Path(
        args.signing_key_file
        or env.get("DB_SYNC_TOKEN_SIGNING_KEY_FILE")
        or (data_dir / "signing-key.pem")
    ).expanduser().resolve()
    run_node_script(repo_root, "generate-signing-key.mjs", [str(signing_key_file)], env)

    base_url = f"http://{args.host}:{args.port}"
    siwe_domain = f"{args.host}:{args.port}"
    env.update(
        {
            "DB_SYNC_PORT": str(args.port),
            "DB_SYNC_DATA_DIR": str(data_dir),
            "DB_SYNC_TOKEN_SIGNER": "file",
            "DB_SYNC_TOKEN_SIGNING_KEY_FILE": str(signing_key_file),
            "DB_SYNC_KEY_STORE": "file",
            "DB_SYNC_TOKEN_ISSUER": base_url,
            "DB_SYNC_TOKEN_AUDIENCE": DEFAULT_TOKEN_AUDIENCE,
            "DB_SYNC_SIWE_DOMAINS": ",".join(sorted({siwe_domain, f"localhost:{args.port}", f"127.0.0.1:{args.port}"})),
        }
    )

    with log_file.open("a", encoding="utf-8") as stream:
        stream.write(f"\n=== cli-e2e db-sync start {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
        stream.flush()
        process = subprocess.Popen(
            ["node", str(entry)],
            stdout=stream,
            stderr=stream,
            cwd=str(repo_root),
            env=env,
            start_new_session=True,
        )

    if not wait_health(base_url, args.startup_timeout_s, args.poll_interval_s):
        terminate_process(process.pid, force=False)
        fail(
            "db-sync server failed health check before timeout",
            base_url=base_url,
            pid=process.pid,
            log_file=str(log_file),
        )

    pid_file.write_text(f"{process.pid}\n", encoding="utf-8")

    minted = None
    if args.mint_auth:
        if not auth_path:
            terminate_process(process.pid, force=False)
            fail("--mint-auth requires --auth-path")
        minted = run_node_script(
            repo_root,
            "siwe-login.mjs",
            ["--server", base_url, "--domain", siwe_domain, "--write-auth", str(auth_path)],
            env,
        )

    print(
        json.dumps(
            {
                "status": "ok",
                "pid": process.pid,
                "pid_file": str(pid_file),
                "log_file": str(log_file),
                "base_url": base_url,
                "data_dir": str(data_dir),
                "token_issuer": base_url,
                "token_audience": DEFAULT_TOKEN_AUDIENCE,
                "signing_key_file": str(signing_key_file),
                "auth_path": str(auth_path) if auth_path else None,
                "minted_address": minted.get("address") if isinstance(minted, dict) else None,
            }
        )
    )


def stop_server(args: argparse.Namespace) -> None:
    pid_file = Path(args.pid_file).expanduser().resolve()
    pid = load_pid(pid_file)

    if pid is None:
        print(json.dumps({"status": "ok", "stopped": False, "reason": "pid-file-missing-or-empty", "pid_file": str(pid_file)}))
        return

    if not process_running(pid):
        try:
            pid_file.unlink(missing_ok=True)
        except OSError:
            pass
        print(json.dumps({"status": "ok", "stopped": False, "reason": "process-not-running", "pid": pid, "pid_file": str(pid_file)}))
        return

    if not terminate_process(pid, force=False):
        fail("db-sync server stop failed", pid=pid, signal="SIGTERM", pid_file=str(pid_file))
    deadline = time.time() + args.shutdown_timeout_s
    while time.time() < deadline:
        if not process_running(pid):
            pid_file.unlink(missing_ok=True)
            print(json.dumps({"status": "ok", "stopped": True, "signal": "SIGTERM", "pid": pid, "pid_file": str(pid_file)}))
            return
        time.sleep(args.poll_interval_s)

    if not terminate_process(pid, force=True):
        fail("db-sync server force stop failed", pid=pid, signal="SIGKILL", pid_file=str(pid_file))
    pid_file.unlink(missing_ok=True)
    print(json.dumps({"status": "ok", "stopped": True, "signal": "SIGKILL", "pid": pid, "pid_file": str(pid_file)}))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage db-sync local server for cli-e2e sync tests")
    subparsers = parser.add_subparsers(dest="command", required=True)

    start = subparsers.add_parser("start", help="Start server and wait for /health")
    start.add_argument("--repo-root", required=True)
    start.add_argument("--pid-file", required=True)
    start.add_argument("--log-file", required=True)
    start.add_argument("--data-dir", required=True)
    start.add_argument("--host", default="127.0.0.1")
    start.add_argument("--port", type=int, default=8080)
    start.add_argument("--startup-timeout-s", type=float, default=25.0)
    start.add_argument("--poll-interval-s", type=float, default=0.5)
    start.add_argument("--auth-path", default="~/logseq/auth.json")
    start.add_argument("--mint-auth", action="store_true", help="Sign in with a throwaway wallet and write the token to --auth-path")
    start.add_argument("--signing-key-file", help="RSA private key PEM for the file token signer (default: <data-dir>/signing-key.pem)")

    stop = subparsers.add_parser("stop", help="Stop server if running")
    stop.add_argument("--pid-file", required=True)
    stop.add_argument("--shutdown-timeout-s", type=float, default=10.0)
    stop.add_argument("--poll-interval-s", type=float, default=0.25)

    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "start":
        start_server(args)
    elif args.command == "stop":
        stop_server(args)
    else:
        fail("unknown command", command=args.command)


if __name__ == "__main__":
    main()
