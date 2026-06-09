#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${KNOTE_BIN:-${ROOT}/bin/knote}"
DEFAULT_PYTHON="python3"
if [[ -x "/usr/bin/python3" ]]; then
  DEFAULT_PYTHON="/usr/bin/python3"
fi
PYTHON="${KNOTE_PYTHON:-${PYTHON:-${DEFAULT_PYTHON}}}"
TMPDIR_ROOT="${TMPDIR:-/tmp}"
WORKSPACE="$(mktemp -d "${TMPDIR_ROOT%/}/knote-eino-proxy.XXXXXX")"
SMOKE_BIN_DIR=""

source "${ROOT}/scripts/lib/eino_local_proxy_env.sh"

cleanup() {
  rm -rf "${WORKSPACE}"
  if [[ -n "${SMOKE_BIN_DIR}" ]]; then
    rm -rf "${SMOKE_BIN_DIR}"
  fi
}
trap cleanup EXIT

cd "${ROOT}"

knote_configure_eino_local_proxy_env
export KNOTE_KAG_FAKE="${KNOTE_KAG_FAKE:-1}"
knote_require_eino_api_key

if [[ ! -x "${BIN}" ]]; then
  CGO_ENABLED=0 go build -o "${BIN}" ./cmd/knote
fi

prepare_smoke_bin() {
  if [[ "$(uname -s)" != "Darwin" || "${KNOTE_SMOKE_FORCE_BIN:-}" != "1" ]]; then
    printf '%s' "${BIN}"
    return 0
  fi
  if [[ -z "${SMOKE_BIN_DIR}" ]]; then
    SMOKE_BIN_DIR="$(mktemp -d "${TMPDIR_ROOT%/}/knote-smoke-bin.XXXXXX")"
  fi
  local target="${SMOKE_BIN_DIR}/eino-proxy-knote"
  cp "${BIN}" "${target}"
  chmod +x "${target}"
  xattr -c "${target}" >/dev/null 2>&1 || true
  codesign --force --sign - "${target}" >/dev/null 2>&1 || true
  printf '%s' "${target}"
}

echo "==> Probing OpenAI-compatible model endpoint: ${KNOTE_EINO_BASE_URL}"
knote_probe_eino_local_proxy "${PYTHON}"

mkdir -p "${WORKSPACE}/sources"
cp -R "${ROOT}/tests/fixtures/basic-kb/sources/." "${WORKSPACE}/sources/"

echo "==> Running Eino TUI smoke against local OpenAI-compatible proxy"
TUI_TARGET=(--bin "${BIN}")
if [[ "$(uname -s)" == "Darwin" && "${KNOTE_SMOKE_FORCE_BIN:-}" != "1" ]]; then
  TUI_TARGET=(--go-run)
elif [[ "$(uname -s)" == "Darwin" ]]; then
  TUI_TARGET=(--bin "$(prepare_smoke_bin)")
fi
"${PYTHON}" tests/smoke/tui_smoke.py \
  "${TUI_TARGET[@]}" \
  --workspace "${WORKSPACE}" \
  --scenario eino-local-proxy

echo "Eino local proxy smoke passed"
