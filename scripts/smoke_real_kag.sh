#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${KNOTE_PYTHON:-python3}"
HOST="${KNOTE_KAG_HOST:-http://127.0.0.1:8887}"
TMPDIR_ROOT="${TMPDIR:-/tmp}"
WORKSPACE="${KNOTE_REAL_KAG_WORKSPACE:-$(mktemp -d "${TMPDIR_ROOT%/}/knote-real-kag.XXXXXX")}"
CREATED_WORKSPACE=0

if [[ -z "${KNOTE_REAL_KAG_WORKSPACE:-}" ]]; then
  CREATED_WORKSPACE=1
fi

cleanup() {
  if [[ "${CREATED_WORKSPACE}" == "1" && "${KEEP_KNOTE_REAL_KAG_WORKSPACE:-}" != "1" ]]; then
    rm -rf "${WORKSPACE}"
  fi
}
trap cleanup EXIT

cd "${ROOT}"

if [[ "${CREATED_WORKSPACE}" == "1" ]]; then
  mkdir -p "${WORKSPACE}/sources"
  cp -R "${ROOT}/tests/fixtures/basic-kb/sources/." "${WORKSPACE}/sources/"
  git -C "${WORKSPACE}" init -q
fi

echo "==> Running real KAG smoke against ${HOST}"
"${PYTHON}" tests/smoke/kag_real_smoke.py \
  --adapter "${ROOT}/adapters/kag/knote_kag_adapter.py" \
  --workspace "${WORKSPACE}" \
  --host "${HOST}"

echo "real KAG smoke passed: ${WORKSPACE}"
