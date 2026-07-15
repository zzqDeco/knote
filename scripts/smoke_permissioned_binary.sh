#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${KNOTE_KAG_FAKE+x}" == "x" ]]; then
  printf '%s\n' '{"status":"fail","stage":"preflight","code":"fake_mode_environment_present"}' >&2
  exit 2
fi

unset KNOTE_KAG_FAKE
export PYTHONDONTWRITEBYTECODE=1

PYTHON_BIN="${KNOTE_PERMISSIONED_BINARY_PYTHON:-python3}"
exec "${PYTHON_BIN}" "${ROOT}/tests/smoke/permissioned_binary_acceptance.py" "$@"
