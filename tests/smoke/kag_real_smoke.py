#!/usr/bin/env python3
"""Manual real OpenSPG/KAG smoke for the knote adapter."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Any


def ensure_real_kag(host: str) -> None:
    try:
        __import__("kag")
    except Exception as exc:  # pragma: no cover - only runs in manual envs
        raise SystemExit(f"openspg-kag is not importable from {sys.executable}: {exc}") from exc
    try:
        with urllib.request.urlopen(host, timeout=5) as response:
            if response.status >= 500:
                raise SystemExit(f"OpenSPG host returned status {response.status}: {host}")
    except Exception as exc:  # pragma: no cover - only runs in manual envs
        raise SystemExit(f"OpenSPG host is not reachable at {host}: {exc}") from exc


def call_adapter(adapter: Path, workspace: Path, host: str, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = {
        "id": method.replace(".", "_"),
        "method": method,
        "params": {
            "workspace": str(workspace),
            "host": host,
            "runtime_dir": str(workspace / ".knote" / "kag-runtime"),
            **(params or {}),
        },
    }
    env = os.environ.copy()
    env.pop("KNOTE_KAG_FAKE", None)
    proc = subprocess.run(
        [sys.executable, str(adapter)],
        input=json.dumps(payload) + "\n",
        text=True,
        capture_output=True,
        cwd=adapter.parents[2],
        env=env,
        timeout=300,
    )
    if proc.returncode != 0:
        raise SystemExit(f"{method} failed with exit {proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")
    lines = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    if not lines:
        raise SystemExit(f"{method} returned no NDJSON output\nstderr:\n{proc.stderr}")
    last = lines[-1]
    if last.get("type") == "error":
        raise SystemExit(f"{method} adapter error: {last.get('error')}\nstderr:\n{proc.stderr}")
    if last.get("type") != "result":
        raise SystemExit(f"{method} did not end with a result: {last}")
    return last


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--adapter", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--host", default="http://127.0.0.1:8887")
    args = parser.parse_args()

    adapter = Path(args.adapter).resolve()
    workspace = Path(args.workspace).resolve()
    ensure_real_kag(args.host)

    for method, params in [
        ("kag.health", None),
        ("kag.build", None),
        ("kag.query", {"query": "What does this knowledge base contain?"}),
        ("kag.explain", {"query": "What evidence supports the answer?"}),
    ]:
        result = call_adapter(adapter, workspace, args.host, method, params)
        print(json.dumps({"method": method, "message": result.get("message"), "data": result.get("data")}, ensure_ascii=False))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
