#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${KNOTE_PERMISSIONED_GRAPH_REAL_SMOKE:-}" != "1" ]]; then
  echo "SKIP: set KNOTE_PERMISSIONED_GRAPH_REAL_SMOKE=1 to run the disposable real-service smoke."
  exit 0
fi

PYTHON="${KNOTE_PYTHON:-python3}"
FGA_VERSION="v0.7.17"
DEFAULT_OPENFGA_IMAGE="openfga/openfga:v1.15.1@sha256:8543200bf85878c968d73da46c4f0e31ba1f63ed3675b71122f1133b0e9d97eb"
DEFAULT_OPENFGA_SERVER_VERSION="v1.15.1@sha256:8543200bf85878c968d73da46c4f0e31ba1f63ed3675b71122f1133b0e9d97eb"
DEFAULT_OPENSPG_SERVER_VERSION="v0.8.0@sha256:fe6708deef9ebb8da8da7b1cb643e83b827769a5be8811961311639aa1f2cb88"
DEFAULT_OPENSPG_COMPOSE_FILE="${ROOT}/tests/fixtures/permissioned-graph-real/docker-compose.yml"
OPENFGA_IMAGE="${KNOTE_OPENFGA_IMAGE:-${DEFAULT_OPENFGA_IMAGE}}"
TMPDIR_ROOT="${TMPDIR:-/tmp}"
RUN_ROOT="$(mktemp -d "${TMPDIR_ROOT%/}/knote-permissioned-graph-real.XXXXXX")"
WORKSPACE="${RUN_ROOT}/workspace"
FGA_BIN="${KNOTE_FGA_BIN:-}"
OPENFGA_CONTAINER=""
OPENFGA_API_URL="${KNOTE_OPENFGA_API_URL:-}"
OPENFGA_SERVER_VERSION="${KNOTE_OPENFGA_SERVER_VERSION:-}"
OPENSPG_SERVER_VERSION="${KNOTE_OPENSPG_SERVER_VERSION:-}"
OPENFGA_VERSION_VERIFICATION=""
OPENSPG_VERSION_VERIFICATION=""
OPENSPG_COMPOSE_FILE="${KNOTE_OPENSPG_COMPOSE_FILE:-${DEFAULT_OPENSPG_COMPOSE_FILE}}"
OPENSPG_COMPOSE_PROJECT=""
KAG_HOST="${KNOTE_KAG_HOST:-}"

fail_preflight() {
  echo "PRECHECK FAILED: $1" >&2
  exit 2
}

cleanup() {
  status=$?
  trap - EXIT
  cleanup_failed=0
  if [[ -n "${OPENFGA_CONTAINER}" ]]; then
    if ! docker rm -f "${OPENFGA_CONTAINER}" >/dev/null 2>&1; then
      cleanup_failed=1
    fi
  fi
  if [[ -n "${OPENSPG_COMPOSE_PROJECT}" ]]; then
    if ! docker compose -p "${OPENSPG_COMPOSE_PROJECT}" -f "${OPENSPG_COMPOSE_FILE}" \
      down -v --remove-orphans >/dev/null 2>&1; then
      cleanup_failed=1
    fi
  fi
  if [[ "${KEEP_KNOTE_PERMISSIONED_GRAPH_REAL_WORKSPACE:-}" == "1" ]]; then
    echo "retained public synthetic workspace: ${WORKSPACE}"
  else
    rm -rf "${RUN_ROOT}"
  fi
  if [[ "${cleanup_failed}" == "1" ]]; then
    echo "CLEANUP FAILED: one or more disposable service resources were not removed." >&2
    if [[ "${status}" == "0" ]]; then
      status=1
    fi
  fi
  exit "${status}"
}
trap cleanup EXIT

for command in "${PYTHON}" curl go; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    fail_preflight "required command is unavailable: ${command}"
  fi
done

if ! "${PYTHON}" -c 'import kag' >/dev/null 2>&1; then
  fail_preflight "openspg-kag is not importable from KNOTE_PYTHON"
fi

if [[ -z "${KAG_HOST}" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    fail_preflight "Docker is required when KNOTE_KAG_HOST is not set"
  fi
  if ! docker compose version >/dev/null 2>&1; then
    fail_preflight "Docker Compose is required when KNOTE_KAG_HOST is not set"
  fi
  if [[ ! -f "${OPENSPG_COMPOSE_FILE}" ]]; then
    fail_preflight "OpenSPG Compose file is unavailable"
  fi
  if [[ "${OPENSPG_COMPOSE_FILE}" == "${DEFAULT_OPENSPG_COMPOSE_FILE}" ]]; then
    if [[ -n "${OPENSPG_SERVER_VERSION}" && "${OPENSPG_SERVER_VERSION}" != "${DEFAULT_OPENSPG_SERVER_VERSION}" ]]; then
      fail_preflight "KNOTE_OPENSPG_SERVER_VERSION does not match the pinned OpenSPG Compose stack"
    fi
    OPENSPG_SERVER_VERSION="${DEFAULT_OPENSPG_SERVER_VERSION}"
    OPENSPG_VERSION_VERIFICATION="repository-pinned-image-digest"
  elif [[ -z "${OPENSPG_SERVER_VERSION}" ]]; then
    fail_preflight "KNOTE_OPENSPG_SERVER_VERSION is required with a custom OpenSPG Compose file"
  else
    OPENSPG_VERSION_VERIFICATION="caller-declared"
  fi
  OPENSPG_COMPOSE_PROJECT="knote-permissioned-graph-${$}"
  if ! docker compose -p "${OPENSPG_COMPOSE_PROJECT}" -f "${OPENSPG_COMPOSE_FILE}" up -d \
    >"${RUN_ROOT}/openspg-compose.log" 2>&1; then
    fail_preflight "could not start the pinned disposable OpenSPG stack"
  fi
  port_line="$(docker compose -p "${OPENSPG_COMPOSE_PROJECT}" -f "${OPENSPG_COMPOSE_FILE}" \
    port server 8887 2>/dev/null | head -n 1)"
  openspg_port="${port_line##*:}"
  if [[ -z "${openspg_port}" || "${openspg_port}" == "${port_line}" ]]; then
    fail_preflight "could not resolve the disposable OpenSPG port"
  fi
  KAG_HOST="http://127.0.0.1:${openspg_port}"
  ready=0
  for ((_attempt = 1; _attempt <= 180; _attempt++)); do
    if curl -fsS --max-time 1 "${KAG_HOST}/" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  if [[ "${ready}" != "1" ]]; then
    fail_preflight "disposable OpenSPG did not become healthy"
  fi
else
  if [[ "${KNOTE_OPENSPG_DISPOSABLE:-}" != "1" ]]; then
    fail_preflight "KNOTE_OPENSPG_DISPOSABLE=1 is required for an external KNOTE_KAG_HOST"
  fi
  if [[ -z "${OPENSPG_SERVER_VERSION}" ]]; then
    fail_preflight "KNOTE_OPENSPG_SERVER_VERSION is required for an external OpenSPG endpoint"
  fi
  OPENSPG_VERSION_VERIFICATION="caller-declared"
fi

if [[ -z "${FGA_BIN}" ]]; then
  mkdir -p "${RUN_ROOT}/bin"
  if ! GOBIN="${RUN_ROOT}/bin" GOTOOLCHAIN=go1.25.12 \
    go install "github.com/openfga/cli/cmd/fga@${FGA_VERSION}" \
    >"${RUN_ROOT}/fga-install.log" 2>&1; then
    fail_preflight "could not install the pinned OpenFGA CLI ${FGA_VERSION}"
  fi
  FGA_BIN="${RUN_ROOT}/bin/fga"
fi

if [[ ! -x "${FGA_BIN}" ]]; then
  fail_preflight "KNOTE_FGA_BIN is not executable"
fi

if [[ -z "${OPENFGA_API_URL}" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    fail_preflight "Docker is required when KNOTE_OPENFGA_API_URL is not set"
  fi
  if [[ "${OPENFGA_IMAGE}" == "${DEFAULT_OPENFGA_IMAGE}" ]]; then
    if [[ -n "${OPENFGA_SERVER_VERSION}" && "${OPENFGA_SERVER_VERSION}" != "${DEFAULT_OPENFGA_SERVER_VERSION}" ]]; then
      fail_preflight "KNOTE_OPENFGA_SERVER_VERSION does not match the pinned OpenFGA image"
    fi
    OPENFGA_SERVER_VERSION="${DEFAULT_OPENFGA_SERVER_VERSION}"
    OPENFGA_VERSION_VERIFICATION="repository-pinned-image-digest"
  elif [[ -z "${OPENFGA_SERVER_VERSION}" ]]; then
    fail_preflight "KNOTE_OPENFGA_SERVER_VERSION is required when KNOTE_OPENFGA_IMAGE overrides the pinned image"
  else
    OPENFGA_VERSION_VERIFICATION="caller-declared"
  fi
  OPENFGA_CONTAINER="knote-openfga-real-${$}"
  if ! docker run -d --rm --name "${OPENFGA_CONTAINER}" \
    -p 127.0.0.1::8080 "${OPENFGA_IMAGE}" run \
    >"${RUN_ROOT}/openfga-container.log" 2>&1; then
    fail_preflight "could not start ${OPENFGA_IMAGE}"
  fi
  port_line="$(docker port "${OPENFGA_CONTAINER}" 8080/tcp 2>/dev/null | head -n 1)"
  openfga_port="${port_line##*:}"
  if [[ -z "${openfga_port}" || "${openfga_port}" == "${port_line}" ]]; then
    fail_preflight "could not resolve the disposable OpenFGA port"
  fi
  OPENFGA_API_URL="http://127.0.0.1:${openfga_port}"
  unset KNOTE_OPENFGA_API_TOKEN
  ready=0
  for ((_attempt = 1; _attempt <= 30; _attempt++)); do
    if curl -fsS --max-time 1 "${OPENFGA_API_URL}/healthz" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  if [[ "${ready}" != "1" ]]; then
    fail_preflight "disposable OpenFGA did not become healthy"
  fi
elif [[ -z "${OPENFGA_SERVER_VERSION}" ]]; then
  fail_preflight "KNOTE_OPENFGA_SERVER_VERSION is required for an external OpenFGA endpoint"
else
  OPENFGA_VERSION_VERIFICATION="caller-declared"
fi

mkdir -p "${WORKSPACE}"
chmod 700 "${WORKSPACE}"

"${PYTHON}" "${ROOT}/tests/smoke/permissioned_graph_real_smoke.py" \
  --live \
  --adapter "${ROOT}/adapters/kag/knote_kag_adapter.py" \
  --fixture "${ROOT}/tests/fixtures/permissioned-graph-real/fixture.json" \
  --provider "${ROOT}/tests/fixtures/permissioned-graph-real/permissioned_graph_provider.py" \
  --model "${ROOT}/internal/authz/model/authorization.fga" \
  --workspace "${WORKSPACE}" \
  --kag-host "${KAG_HOST}" \
  --kag-namespace-prefix "${KNOTE_KAG_NAMESPACE_PREFIX:-KnotePermissionedGraphReal}" \
  --kag-language "${KNOTE_KAG_LANGUAGE:-en}" \
  --fga-bin "${FGA_BIN}" \
  --openfga-api-url "${OPENFGA_API_URL}" \
  --expected-fga-cli-version "${FGA_VERSION}" \
  --expected-kag-version "0.8.0" \
  --expected-knext-version "0.8.0" \
  --openfga-server-version "${OPENFGA_SERVER_VERSION}" \
  --openspg-server-version "${OPENSPG_SERVER_VERSION}" \
  --openfga-version-verification "${OPENFGA_VERSION_VERIFICATION}" \
  --openspg-version-verification "${OPENSPG_VERSION_VERIFICATION}" \
  --disposable-openspg-stack \
  --index-ready-timeout "${KNOTE_PERMISSIONED_GRAPH_INDEX_READY_TIMEOUT:-30}" \
  --revocation-timeout "${KNOTE_PERMISSIONED_GRAPH_REVOCATION_TIMEOUT:-10}"
