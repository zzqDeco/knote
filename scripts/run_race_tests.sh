#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Keep broad package trees here so new concurrency-sensitive code is covered
# without duplicating their current subpackages in CI configuration.
RACE_PACKAGE_PATTERNS=(
  ./cmd/knote
  ./internal/audit
  ./internal/authz
  ./internal/catalog
  ./internal/connector
  ./internal/governance
  ./internal/identity
  ./internal/knowledge/...
  ./internal/policysim
  ./internal/repository/...
  ./internal/residency
  ./internal/runtime
  ./internal/runtime/eino
)

usage() {
  cat <<'EOF'
Usage: scripts/run_race_tests.sh [--list|--list-expanded]

With no argument, expands the canonical package patterns and runs each Go
package separately under the race detector. --list prints the source patterns;
--list-expanded prints the concrete Go package import paths.
EOF
}

list_patterns() {
  printf '%s\n' "${RACE_PACKAGE_PATTERNS[@]}"
}

list_expanded() {
  cd "${ROOT}"
  go list "${RACE_PACKAGE_PATTERNS[@]}"
}

case "${1:-}" in
  --list)
    list_patterns
    exit 0
    ;;
  --list-expanded)
    list_expanded
    exit 0
    ;;
  "")
    ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

cd "${ROOT}"
expanded_packages="$(list_expanded)"
if [[ -z "${expanded_packages}" ]]; then
  printf '%s\n' 'race package manifest expanded to no packages' >&2
  exit 1
fi

package_count="$(printf '%s\n' "${expanded_packages}" | wc -l | tr -d '[:space:]')"
package_index=0
while IFS= read -r package; do
  [[ -n "${package}" ]] || continue
  package_index=$((package_index + 1))
  printf '==> race package %d/%d: %s\n' "${package_index}" "${package_count}" "${package}"
  if ! KNOTE_KAG_FAKE="${KNOTE_KAG_FAKE:-1}" go test -race -count=1 "${package}"; then
    printf 'race tests failed for %s\n' "${package}" >&2
    exit 1
  fi
done <<< "${expanded_packages}"
