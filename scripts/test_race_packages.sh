#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER="${ROOT}/scripts/run_race_tests.sh"

fail() {
  printf 'race package self-check failed: %s\n' "$*" >&2
  exit 1
}

manifest="$("${RUNNER}" --list)"
expanded="$("${RUNNER}" --list-expanded)"

[[ -n "${manifest}" ]] || fail 'manifest is empty'
[[ -n "${expanded}" ]] || fail 'manifest expands to no Go packages'

duplicates="$(printf '%s\n' "${manifest}" | sort | uniq -d)"
[[ -z "${duplicates}" ]] || fail "duplicate manifest entries: ${duplicates}"

expanded_duplicates="$(printf '%s\n' "${expanded}" | sort | uniq -d)"
[[ -z "${expanded_duplicates}" ]] || fail "duplicate expanded packages: ${expanded_duplicates}"

for required in ./internal/repository/... ./internal/knowledge/...; do
  count="$(printf '%s\n' "${manifest}" | grep -Fxc "${required}" || true)"
  [[ "${count}" == 1 ]] || fail "required recursive pattern ${required} must appear exactly once"
done

while IFS= read -r recursive; do
  [[ -n "${recursive}" ]] || continue
  root="${recursive%/...}"
  while IFS= read -r pattern; do
    [[ -n "${pattern}" && "${pattern}" != "${recursive}" ]] || continue
    case "${pattern}" in
      "${root}"|"${root}"/*)
        fail "${pattern} is already covered by recursive pattern ${recursive}"
        ;;
    esac
  done <<< "${manifest}"
done < <(printf '%s\n' "${manifest}" | grep '/\.\.\.$' || true)

for integration in .github/workflows/ci.yml scripts/verify_phase3_acceptance.sh; do
  path="${ROOT}/${integration}"
  runner_count="$(grep -Fc 'scripts/run_race_tests.sh' "${path}" || true)"
  [[ "${runner_count}" == 1 ]] || fail "${integration} must invoke the canonical runner exactly once"

  self_check_count="$(grep -Fc 'scripts/test_race_packages.sh' "${path}" || true)"
  [[ "${self_check_count}" == 1 ]] || fail "${integration} must invoke this self-check exactly once"

  if grep -n -- '-race' "${path}" >/dev/null; then
    fail "${integration} contains an inline race command instead of the canonical runner"
  fi
done

printf 'Race package manifest self-check passed (%s concrete packages).\n' \
  "$(printf '%s\n' "${expanded}" | wc -l | tr -d '[:space:]')"
