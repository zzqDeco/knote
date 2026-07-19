#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENFGA_IMAGE="openfga/openfga:v1.15.1@sha256:8543200bf85878c968d73da46c4f0e31ba1f63ed3675b71122f1133b0e9d97eb"
FGA_MODULE="github.com/openfga/cli/cmd/fga@v0.7.17"
TEMP_ROOT="${TMPDIR:-/tmp}"
TEMP_DIR="$(mktemp -d "${TEMP_ROOT%/}/knote-phase3-openfga.XXXXXX")"
CONTAINER_NAME="knote-phase3-openfga-${GITHUB_RUN_ID:-$$}-${RANDOM}"
CONTAINER_STARTED=0

fail() {
  printf 'phase3 OpenFGA smoke failed: %s\n' "$1" >&2
  exit 1
}

cleanup() {
  local status=$?
  local cleanup_failed=0
  trap - EXIT

  if [[ "${CONTAINER_STARTED}" == "1" ]]; then
    docker rm --force "${CONTAINER_NAME}" >/dev/null 2>&1 || cleanup_failed=1
  fi
  rm -rf "${TEMP_DIR}" || cleanup_failed=1

  if [[ "${cleanup_failed}" == "1" && "${status}" == "0" ]]; then
    printf '%s\n' 'phase3 OpenFGA smoke failed: cleanup' >&2
    status=1
  fi
  exit "${status}"
}
trap cleanup EXIT

for command in docker go python3; do
  command -v "${command}" >/dev/null 2>&1 || fail "missing_${command}"
done
docker info >/dev/null 2>&1 || fail docker_unavailable

mkdir -p "${TEMP_DIR}/bin"
GOBIN="${TEMP_DIR}/bin" GOTOOLCHAIN=go1.25.12 go install "${FGA_MODULE}"
FGA_BIN="${TEMP_DIR}/bin/fga"
go version -m "${FGA_BIN}" |
  grep -Eq '^[[:space:]]*mod[[:space:]]+github.com/openfga/cli[[:space:]]+v0\.7\.17([[:space:]]|$)' ||
  fail fga_version_mismatch

API_TOKEN="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
[[ -n "${API_TOKEN}" ]] || fail token_generation

umask 077
ENV_FILE="${TEMP_DIR}/openfga.env"
{
  printf '%s\n' 'OPENFGA_DATASTORE_ENGINE=memory'
  printf '%s\n' 'OPENFGA_AUTHN_METHOD=preshared'
  printf 'OPENFGA_AUTHN_PRESHARED_KEYS=%s\n' "${API_TOKEN}"
  printf '%s\n' 'OPENFGA_PLAYGROUND_ENABLED=false'
} >"${ENV_FILE}"

docker run --detach --rm \
  --name "${CONTAINER_NAME}" \
  --publish '127.0.0.1::8080' \
  --env-file "${ENV_FILE}" \
  "${OPENFGA_IMAGE}" run >/dev/null
CONTAINER_STARTED=1

PUBLISHED="$(docker port "${CONTAINER_NAME}" 8080/tcp | sed -n '1p')"
PORT="${PUBLISHED##*:}"
[[ "${PORT}" =~ ^[0-9]+$ ]] || fail published_port
API_URL="http://127.0.0.1:${PORT}"

export FGA_API_URL="${API_URL}"
export FGA_API_TOKEN="${API_TOKEN}"

ready=0
for _ in $(seq 1 60); do
  if "${FGA_BIN}" store list >/dev/null 2>&1; then
    ready=1
    break
  fi
  if [[ "$(docker inspect --format '{{.State.Running}}' "${CONTAINER_NAME}" 2>/dev/null || true)" != "true" ]]; then
    break
  fi
  sleep 1
done
[[ "${ready}" == "1" ]] || fail service_not_ready

STORE_JSON="$("${FGA_BIN}" store create --name knote-phase3-openfga-smoke)"
STORE_ID="$(python3 -c 'import json, sys; print(json.load(sys.stdin)["store"]["id"])' <<<"${STORE_JSON}")"
[[ -n "${STORE_ID}" ]] || fail store_create

MODEL_JSON="$("${FGA_BIN}" model write --file "${ROOT}/internal/authz/model/authorization.fga" --store-id "${STORE_ID}" --format fga)"
MODEL_ID="$(python3 -c 'import json, sys; print(json.load(sys.stdin)["authorization_model_id"])' <<<"${MODEL_JSON}")"
[[ -n "${MODEL_ID}" ]] || fail model_write

KNOTE_PHASE3_OPENFGA_LIVE=1 \
KNOTE_OPENFGA_ENDPOINT="${API_URL}" \
KNOTE_OPENFGA_STORE_ID="${STORE_ID}" \
KNOTE_OPENFGA_MODEL_ID="${MODEL_ID}" \
KNOTE_OPENFGA_API_TOKEN="${API_TOKEN}" \
  go test -count=1 -run '^TestPhase3OpenFGALiveSmoke$' ./internal/authz

printf '%s\n' 'phase3 OpenFGA smoke passed'
