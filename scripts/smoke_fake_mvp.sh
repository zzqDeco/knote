#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${KNOTE_BIN:-${ROOT}/bin/knote}"
PYTHON="${PYTHON:-python3}"
TMPDIR_ROOT="${TMPDIR:-/tmp}"
WORKSPACE="$(mktemp -d "${TMPDIR_ROOT%/}/knote-fake-mvp.XXXXXX")"

cleanup() {
  rm -rf "${WORKSPACE}"
  rm -rf "${ROOT}/tests/fixtures/basic-kb/.knote"
}
trap cleanup EXIT

cd "${ROOT}"

if [[ ! -x "${BIN}" ]]; then
  CGO_ENABLED=0 go build -o "${BIN}" ./cmd/knote
fi

TUI_TARGET=(--bin "${BIN}")
if [[ "$(uname -s)" == "Darwin" && "${KNOTE_SMOKE_FORCE_BIN:-}" != "1" ]]; then
  TUI_TARGET=(--go-run)
fi

echo "==> PTY startup smoke on tests/fixtures/basic-kb"
KNOTE_KAG_FAKE=1 "${PYTHON}" tests/smoke/tui_smoke.py \
  "${TUI_TARGET[@]}" \
  --workspace "${ROOT}/tests/fixtures/basic-kb" \
  --scenario startup

echo "==> Preparing temporary fake MVP workspace: ${WORKSPACE}"
mkdir -p "${WORKSPACE}/sources"
cp -R "${ROOT}/tests/fixtures/basic-kb/sources/." "${WORKSPACE}/sources/"
git -C "${WORKSPACE}" init -q
git -C "${WORKSPACE}" config user.email knote@example.com
git -C "${WORKSPACE}" config user.name knote

echo "==> Running fake KAG build/query/diff/commit/resume/eval smoke"
KNOTE_KAG_FAKE=1 "${PYTHON}" tests/smoke/tui_smoke.py \
  "${TUI_TARGET[@]}" \
  --workspace "${WORKSPACE}" \
  --scenario fake-mvp

test -s "${WORKSPACE}/evals/report.md"
grep -q "adapter_errors: 0" "${WORKSPACE}/evals/report.md"
test -s "${WORKSPACE}/evals/results.jsonl"

echo "fake MVP smoke passed"
