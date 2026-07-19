# Phase 3 Release Evidence Contract

This is the content-free release-evidence schema for issue #97 and epic #90.
It targets `dev` only. It does not authorize a change to `main`, a release
branch, a tag, a published binary, or a GitHub Release.

The tables below are a reusable template, not the status of the commit that
contains this file. Keep dynamic fields `pending` in Git. Record their final
fixed statuses, counts, durations, digests, SHAs, and URLs in the PR and issue
completion comments after CI and review finish on the exact final head. This
avoids a self-referential commit whose evidence SHA changes when the file is
updated. Do not paste raw test logs, environments, assertions, OpenFGA payloads,
provider output, audit ledgers, session data, or protected identifiers.

## Candidate

| Field | Evidence |
|---|---|
| Target branch | `dev` |
| Issue | `#97` |
| Epic | `#90` |
| PR | `pending` |
| Full head SHA | `pending` |
| UTC evidence time | `pending` |
| Hosted CI URL | `pending` |
| Current-head Codex review SHA | `pending` |
| Unresolved verified P1/P2 findings | `pending` |
| Final decision | `NOT READY` until every required row below is `pass` |

## Deterministic release gate

Run from a clean checkout of the full head SHA:

```sh
scripts/verify_phase3_acceptance.sh
```

| Evidence | Required | Observed |
|---|---|---|
| Exit status | `0` | `pending` |
| Final fixed line | `Phase 3 deterministic acceptance passed.` | `pending` |
| Baseline Go tests | `pass` | `pending` |
| Canonical Phase 3 matrix and exact anchors | `pass` | `pending` |
| Python adapter tests | `pass` | `pending` |
| Permissioned graph real-adapter self-test | `pass` | `pending` |
| Exact built-binary smoke | `pass` | `pending` |
| OpenFGA model tests | `pass` | `pending` |
| Shared-package race tests | `pass` | `pending` |
| `go vet ./...` | `pass` | `pending` |
| Linux amd64 build | `pass` | `pending` |
| Windows amd64 build | `pass` | `pending` |

## #97 invariant matrix

| ID | Invariant | Required result | Observed | Evidence anchor |
|---|---|---:|---|---|
| `tenant-collision-isolation` | Colliding external IDs remain tenant isolated | Cross-tenant observations `0`; samples `2` | `pending` | Canonical fixture anchors `2` |
| `identity-fail-closed-replay-safe` | SSO assertion and SCIM lifecycle are fail closed and replay safe | Invalid/replayed/stale/deprovisioned accepts `0`; samples `4` | `pending` | Canonical fixture anchors `4` |
| `connector-acl-failure-never-serves` | Content plus failed/missing ACL never serves | Partial-serving transitions `0`; samples `2` | `pending` | Canonical fixture anchors `2` |
| `durable-connector-convergence` | Duplicate/reordered/crash/DLQ/tombstone/reconciliation converges | Residual diff and resurrection counts `0`; replay digest stable; samples `7` | `pending` | Canonical fixture anchors `7` |
| `user-agent-task-intersection` | Effective access is `user ∩ agent ∩ task` on every protected surface | Incomplete-scope allows `0`; samples `4` | `pending` | Canonical fixture anchors `4` |
| `tool-invocation-and-results-authorized` | Invocation and every returned resource are authorized | Unauthorized callbacks and outputs `0`; samples `4` | `pending` | Canonical fixture anchors `4` |
| `simulation-read-only-oracle-parity` | Simulation is non-mutating and matches the oracle | Before/after digest equal; impact mismatch `0`; samples `14` | `pending` | Canonical fixture anchors `2` |
| `audit-content-free-tamper-evident` | Audit is content free and tamper evident | Forbidden fields `0`; every tamper fixture fails closed; samples `2` | `pending` | Canonical fixture anchors `2` |
| `residency-blocks-storage-egress` | Residency denies before storage or egress | Denied callbacks and bytes `0`; samples `2` | `pending` | Canonical fixture anchors `2` |
| `unauthorized-observability-hidden` | Protected existence/count/page/error/trace/telemetry/governance surfaces do not leak | Canary and unauthorized-section count `0`; samples `5` | `pending` | Canonical fixture anchors `5` |
| `false-allow-zero` | False allow is zero across all cohorts | Top-level `false_allow = 0`; samples `14` | `pending` | Canonical fixture anchors `2` |
| `operational-latency-budgets` | All six Phase 3 budgets are met | Every budget row below is `pass`; samples `145` | `pending` | Canonical fixture anchors `6` |

The detailed test mapping and failure semantics are in
`docs/permissioned-kag-acceptance.md`.

## Budget evidence

Nearest-rank percentiles include every declared sample. A missing, discarded,
timed-out, or malformed sample fails the budget.

| Canonical ID | Metric | Cohort | Required | Observed | Result |
|---|---|---:|---|---:|---|
| `batch-check-latency` | `openfga_batch_check`, P99 | `12` | `<= 100ms`; physical batch `<= 50`; malformed/partial accepts `0` | `pending` | `pending` |
| `connector-lag` | `connector_apply_lag`, max | `1` | `<= 2000ms`; failed-serving advances `0` | `pending` | `pending` |
| `governance-latency` | `governance_view`, max | `2` | `<= 1000ms`; unauthorized fields `0` | `pending` | `pending` |
| `reconciliation-latency` | `full_reconciliation`, max | `1` | `<= 1000ms`; residual protected-state diff `0` | `pending` | `pending` |
| `replay-latency` | `session_replay`, max | `1` | `<= 3000ms`; byte mismatch and unauthorized replay `0` | `pending` | `pending` |
| `revocation-latency` | `revocation_propagation`, P99 | `128` | P99 `<= 100ms`; supplemental P95 `<= 25ms`; stale protected reads `0` | `pending` | `pending` |

Record the canonical fixture digest and validator result:

| Field | Evidence |
|---|---|
| Canonical fixture | `tests/fixtures/phase3-acceptance.json` |
| Fixture version | `phase3-acceptance.v1` |
| Fixture SHA-256 | `pending` |
| `go test -count=1 ./tests/phase3 -run '^TestPhase3AcceptanceMatrix$'` | `pending` |

## Real OpenFGA evidence

Run only after deterministic acceptance:

```sh
scripts/smoke_phase3_openfga.sh
```

| Evidence | Required | Observed |
|---|---|---|
| Exit status | `0` | `pending` |
| Final fixed line | `phase3 OpenFGA smoke passed` | `pending` |
| OpenFGA image | `openfga/openfga:v1.15.1@sha256:8543200bf85878c968d73da46c4f0e31ba1f63ed3675b71122f1133b0e9d97eb` | `pending` |
| OpenFGA CLI | `github.com/openfga/cli/cmd/fga@v0.7.17` | `pending` |
| Complete user-agent-task Check | `allow` | `pending` |
| Incomplete BatchCheck item | `deny` | `pending` |
| Complete BatchCheck item | `allow` | `pending` |
| Post-revocation Check | `deny` | `pending` |
| Container and temporary credential cleanup | `pass` | `pending` |

Do not record temporary endpoint, token, store, model, principal, agent, task, or
document values.

## Governance, audit, and residency evidence

| Surface | Required evidence | Observed |
|---|---|---|
| Governance authorization | Higher-consistency authorization; denied source-call count `0` | `pending` |
| Governance rendering | Deterministic content-free output; unauthorized sections omitted | `pending` |
| Governance audit | Successful view yields a later content-free `governance.view` reference | `pending` |
| Audit durability | Append/reopen/race/crash tests pass | `pending` |
| Audit tamper response | Mutation, truncation, reorder, copy, duplicate, and injected-field fixtures all fail closed | `pending` |
| Audit location | Default is outside workspace or explicit absolute operator path | `pending` |
| Residency storage/process | Disallowed callbacks and bytes `0` | `pending` |
| Residency deny-all egress | `KNOTE_RESIDENCY_EGRESS_REGIONS=none` initializes; connector egress denies before callback | `pending` |
| Residency observability | Only fixed content-free violation references are visible | `pending` |

Reproducible operator commands and expected surfaces are in
`docs/permissioned-kag-operations.md`.

## Hosted and review gate

| Gate | Required | Observed |
|---|---|---|
| PR targets | `dev` | `pending` |
| Hosted checks at full head SHA | all required checks `pass` | `pending` |
| Current-head Codex review | complete | `pending` |
| Verified P1/P2 findings | `0` | `pending` |
| Unresolved severe review threads | `0` | `pending` |
| Merge method | squash merge to `dev` | `pending` |

## Decision

An evaluated candidate remains `NOT READY` while any field is `pending`, any required result
fails, any false allow is nonzero, CI or review targets another SHA, or live
cleanup fails. After every gate passes and the PR is squash-merged to `dev`, the
issue completion record may state `PHASE 3 ACCEPTED ON DEV` with the merge SHA.

That decision closes issue #97 and permits epic #90 to close. It does not create
or authorize a tag, release branch, binary publication, or GitHub Release.
