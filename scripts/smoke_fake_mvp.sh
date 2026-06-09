#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${KNOTE_BIN:-${ROOT}/bin/knote}"
PYTHON="${PYTHON:-python3}"
TMPDIR_ROOT="${TMPDIR:-/tmp}"
WORKSPACE="$(mktemp -d "${TMPDIR_ROOT%/}/knote-fake-mvp.XXXXXX")"
SMOKE_BIN_DIR=""

source "${ROOT}/scripts/lib/eino_local_proxy_env.sh"

cleanup() {
  rm -rf "${WORKSPACE}"
  if [[ -n "${SMOKE_BIN_DIR}" ]]; then
    rm -rf "${SMOKE_BIN_DIR}"
  fi
  rm -rf "${ROOT}/tests/fixtures/basic-kb/.knote"
}
trap cleanup EXIT

cd "${ROOT}"

knote_configure_eino_local_proxy_env
knote_require_eino_api_key

if [[ ! -x "${BIN}" ]]; then
  CGO_ENABLED=0 go build -o "${BIN}" ./cmd/knote
fi

prepare_smoke_bin() {
  local name="$1"
  if [[ "$(uname -s)" != "Darwin" || "${KNOTE_SMOKE_FORCE_BIN:-}" != "1" ]]; then
    printf '%s' "${BIN}"
    return 0
  fi
  if [[ -z "${SMOKE_BIN_DIR}" ]]; then
    SMOKE_BIN_DIR="$(mktemp -d "${TMPDIR_ROOT%/}/knote-smoke-bin.XXXXXX")"
  fi
  local target="${SMOKE_BIN_DIR}/${name}"
  cp "${BIN}" "${target}"
  chmod +x "${target}"
  xattr -c "${target}" >/dev/null 2>&1 || true
  codesign --force --sign - "${target}" >/dev/null 2>&1 || true
  printf '%s' "${target}"
}

echo "==> Probing OpenAI-compatible model endpoint: ${KNOTE_EINO_BASE_URL}"
knote_probe_eino_local_proxy "${PYTHON}"

TUI_TARGET=(--bin "${BIN}")
if [[ "$(uname -s)" == "Darwin" && "${KNOTE_SMOKE_FORCE_BIN:-}" != "1" ]]; then
  TUI_TARGET=(--go-run)
fi
STARTUP_TARGET=("${TUI_TARGET[@]}")
FAKE_TARGET=("${TUI_TARGET[@]}")
if [[ "$(uname -s)" == "Darwin" && "${KNOTE_SMOKE_FORCE_BIN:-}" == "1" ]]; then
  STARTUP_TARGET=(--bin "$(prepare_smoke_bin startup-knote)")
  FAKE_TARGET=(--bin "$(prepare_smoke_bin fake-knote)")
fi

echo "==> PTY startup smoke on tests/fixtures/basic-kb"
KNOTE_KAG_FAKE=1 "${PYTHON}" tests/smoke/tui_smoke.py \
  "${STARTUP_TARGET[@]}" \
  --workspace "${ROOT}/tests/fixtures/basic-kb" \
  --scenario startup

echo "==> Preparing temporary fake MVP workspace: ${WORKSPACE}"
mkdir -p "${WORKSPACE}/sources"
cp -R "${ROOT}/tests/fixtures/basic-kb/sources/." "${WORKSPACE}/sources/"
git -C "${WORKSPACE}" init -q
git -C "${WORKSPACE}" config user.email knote@example.com
git -C "${WORKSPACE}" config user.name knote

echo "==> Running fake KAG build/diff/commit/resume/eval smoke"
KNOTE_KAG_FAKE=1 "${PYTHON}" tests/smoke/tui_smoke.py \
  "${FAKE_TARGET[@]}" \
  --workspace "${WORKSPACE}" \
  --scenario fake-mvp

test -s "${WORKSPACE}/evals/report.md"
grep -q "adapter_errors: 0" "${WORKSPACE}/evals/report.md"
test -s "${WORKSPACE}/evals/results.jsonl"

echo "fake MVP smoke passed"
