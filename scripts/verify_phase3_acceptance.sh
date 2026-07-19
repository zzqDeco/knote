#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"
FGA_CLI_VERSION="v0.7.17"
TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/knote-phase3-acceptance.XXXXXX")"

cleanup() {
  rm -rf "${TEMP_ROOT}"
}
trap cleanup EXIT

cd "${ROOT}"

CGO_ENABLED=0 go build -trimpath -o "${TEMP_ROOT}/knote" ./cmd/knote
scripts/smoke_permissioned_binary.sh --bin "${TEMP_ROOT}/knote"

KNOTE_KAG_FAKE=1 go test -count=1 ./...
"${PYTHON_BIN}" -m unittest discover -s adapters/kag -p '*test*.py'
"${PYTHON_BIN}" tests/smoke/permissioned_graph_real_smoke.py --self-test

GOTOOLCHAIN=go1.25.12 go run "github.com/openfga/cli/cmd/fga@${FGA_CLI_VERSION}" \
  model test --tests internal/authz/model/authorization.fga.yaml

go test -race -count=1 \
  ./internal/audit \
  ./internal/authz \
  ./internal/connector \
  ./internal/governance \
  ./internal/identity \
  ./internal/knowledge/authorized \
  ./internal/policysim \
  ./internal/residency \
  ./internal/runtime \
  ./internal/runtime/eino \
  ./cmd/knote
go vet ./...

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -o "${TEMP_ROOT}/knote-linux-amd64" ./cmd/knote
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -o "${TEMP_ROOT}/knote-windows-amd64.exe" ./cmd/knote
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go test -c -o "${TEMP_ROOT}/knote-identity-windows.test.exe" ./internal/identity
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go test -c -o "${TEMP_ROOT}/knote-connector-windows.test.exe" ./internal/connector
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go test -c -o "${TEMP_ROOT}/knote-audit-windows.test.exe" ./internal/audit

printf '%s\n' 'Phase 3 deterministic acceptance passed.'
