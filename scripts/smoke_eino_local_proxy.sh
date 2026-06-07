#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${KNOTE_BIN:-${ROOT}/bin/knote}"
PYTHON="${KNOTE_PYTHON:-${PYTHON:-python3}}"
TMPDIR_ROOT="${TMPDIR:-/tmp}"
WORKSPACE="$(mktemp -d "${TMPDIR_ROOT%/}/knote-eino-proxy.XXXXXX")"

cleanup() {
  rm -rf "${WORKSPACE}"
}
trap cleanup EXIT

cd "${ROOT}"

export KNOTE_EINO_PROVIDER="${KNOTE_EINO_PROVIDER:-openai-compatible}"
export KNOTE_EINO_MODEL="${KNOTE_EINO_MODEL:-gpt-5.3-codex-spark}"
export KNOTE_EINO_BASE_URL="${KNOTE_EINO_BASE_URL:-http://127.0.0.1:8317/v1}"
export KNOTE_EINO_REASONING_EFFORT="${KNOTE_EINO_REASONING_EFFORT:-low}"
export KNOTE_KAG_FAKE="${KNOTE_KAG_FAKE:-1}"

if [[ -z "${KNOTE_EINO_API_KEY:-}" ]]; then
  config_candidates=()
  if [[ -n "${KNOTE_CLIPROXY_CONFIG:-}" ]]; then
    config_candidates+=("${KNOTE_CLIPROXY_CONFIG}")
  fi
  if [[ -n "${HOME:-}" ]]; then
    config_candidates+=("${HOME}/.cli-proxy-api/config.yaml")
    config_candidates+=("${HOME}/CLIProxyAPI/config.yaml")
  fi
  if command -v brew >/dev/null 2>&1; then
    brew_prefix="$(brew --prefix 2>/dev/null || true)"
    if [[ -n "${brew_prefix}" ]]; then
      config_candidates+=("${brew_prefix}/etc/cliproxyapi.conf")
    fi
  fi
  config_candidates+=("/opt/homebrew/etc/cliproxyapi.conf")
  config_candidates+=("/usr/local/etc/cliproxyapi.conf")

  if command -v ruby >/dev/null 2>&1; then
    for config_path in "${config_candidates[@]}"; do
      if [[ ! -f "${config_path}" ]]; then
        continue
      fi
      candidate_key="$(ruby -ryaml -e 'cfg=YAML.load_file(ARGV[0]) || {}; print Array(cfg["api-keys"] || cfg["api_keys"]).first.to_s' "${config_path}" 2>/dev/null || true)"
      if [[ -n "${candidate_key}" ]]; then
        KNOTE_EINO_API_KEY="${candidate_key}"
        export KNOTE_EINO_API_KEY
        break
      fi
    done
  fi
fi

if [[ -z "${KNOTE_EINO_API_KEY:-}" ]]; then
  echo "KNOTE_EINO_API_KEY is required. Set it explicitly or set KNOTE_CLIPROXY_CONFIG to a CLIProxyAPI config with api-keys." >&2
  echo "Default config paths checked include ~/.cli-proxy-api/config.yaml, ~/CLIProxyAPI/config.yaml, and Homebrew etc/cliproxyapi.conf." >&2
  exit 2
fi

if [[ ! -x "${BIN}" ]]; then
  CGO_ENABLED=0 go build -o "${BIN}" ./cmd/knote
fi

echo "==> Probing OpenAI-compatible model endpoint: ${KNOTE_EINO_BASE_URL}"
"${PYTHON}" - <<'PY'
import json
import os
import sys
import urllib.error
import urllib.request

base = os.environ["KNOTE_EINO_BASE_URL"].rstrip("/")
model = os.environ["KNOTE_EINO_MODEL"]
key = os.environ["KNOTE_EINO_API_KEY"]
req = urllib.request.Request(
    base + "/models",
    headers={"Authorization": "Bearer " + key},
)
try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode("utf-8"))
except urllib.error.HTTPError as exc:
    body = exc.read().decode("utf-8", errors="replace")
    print(f"model endpoint failed: HTTP {exc.code} {body[:200]}", file=sys.stderr)
    raise SystemExit(1)
except Exception as exc:
    print(f"model endpoint failed: {exc}", file=sys.stderr)
    raise SystemExit(1)

items = data.get("data", [])
if not isinstance(items, list):
    items = []
ids = [item.get("id") for item in items if isinstance(item, dict) and item.get("id")]
print(json.dumps({"model_count": len(ids), "target_model": model, "target_listed": model in ids}, ensure_ascii=False))
if model not in ids:
    if not ids:
        print("model endpoint did not return any model ids", file=sys.stderr)
        raise SystemExit(1)
    print(f"target model {model!r} was not listed by /models", file=sys.stderr)
    raise SystemExit(1)
PY

mkdir -p "${WORKSPACE}/sources"
cp -R "${ROOT}/tests/fixtures/basic-kb/sources/." "${WORKSPACE}/sources/"

echo "==> Running Eino TUI smoke against local OpenAI-compatible proxy"
KNOTE_RUNTIME_MODE=eino "${PYTHON}" tests/smoke/tui_smoke.py \
  --bin "${BIN}" \
  --workspace "${WORKSPACE}" \
  --scenario eino-local-proxy

echo "Eino local proxy smoke passed"
