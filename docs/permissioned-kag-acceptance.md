# Phase 3 Permissioned KAG Acceptance

This document is the acceptance contract for issue #97 on `dev`. It proves the
Phase 3 enterprise control and data plane delivered by issues #91 through #96
without weakening the inherited Phase 0-2 authorization, projection, graph,
revocation, and session contracts.

Passing this contract approves only the reviewed `dev` commit. It does not
merge or modify `main`, create a tag, publish an artifact, or create a GitHub
Release.

## Evidence rules

- Every result is bound to one full Git commit SHA and the `dev` target branch.
- The canonical top-level `false_allow` value must be exactly `0`; no
  percentile or retry allowance
  applies to a false allow.
- Hidden, absent, cross-tenant, stale, malformed, and backend-failure fixtures
  must remain indistinguishable on protected surfaces.
- Performance percentiles use nearest rank over the complete declared cohort:
  sort all samples and select `ceil(percentile * sample_count) - 1`. A missing,
  discarded, timed-out, or malformed sample fails the cohort.
- Evidence contains fixed scenario names, counts, durations, digests, versions,
  and pass/fail values only. It must not contain tenant, principal, connector,
  resource, prompt, answer, path, credential, assertion, or provider-output
  values.
- Every named path must exist at the exact candidate commit. Canonical fixture
  anchors must name exact `TestXxx(*testing.T)` declarations.

The deterministic local release-evidence entrypoint introduced by #97 is
`scripts/verify_phase3_acceptance.sh`. It runs the baseline, Python adapter and
real-adapter self-test, built-binary acceptance, OpenFGA model tests, race tests,
vet, and Linux/Windows builds as one fail-fast command. The live OpenFGA
entrypoint introduced by #97 is `scripts/smoke_phase3_openfga.sh`.

The machine-readable contract is
`tests/fixtures/phase3-acceptance.json`. The validator in
`tests/phase3/acceptance_matrix_test.go` requires canonical JSON, issue `97`,
false allow `0`, the complete invariant and budget sets, positive cohorts,
sorted anchors, and exact existing Go test functions.

## Required gate sequence

Run all commands from the repository root on the exact candidate commit.

### 1. Authoritative deterministic entrypoint

```sh
scripts/verify_phase3_acceptance.sh
```

The script takes no arguments. It creates and removes its own temporary
directory and finishes with `Phase 3 deterministic acceptance passed.` only
after every constituent command succeeds. The sections below expose those
commands for diagnosis; running a subset is not equivalent to this entrypoint.

### 2. Baseline constituents

```sh
KNOTE_KAG_FAKE=1 go test ./...
/usr/bin/python3 -m unittest discover -s adapters/kag -p '*test*.py'
CGO_ENABLED=0 go build -o /tmp/knote-check ./cmd/knote
go vet ./...

go test -count=1 ./tests/phase3 -run '^TestPhase3AcceptanceMatrix$'
```

### 3. Phase 3 component and race diagnosis

```sh
go test -count=1 \
  ./internal/identity \
  ./internal/connector \
  ./internal/authz \
  ./internal/policysim \
  ./internal/audit \
  ./internal/residency \
  ./internal/governance \
  ./internal/knowledge/authorized \
  ./internal/knowledge/kag \
  ./internal/runtime \
  ./internal/runtime/eino \
  ./cmd/knote

go test -race -count=1 \
  ./internal/identity \
  ./internal/connector \
  ./internal/authz \
  ./internal/policysim \
  ./internal/audit \
  ./internal/residency \
  ./internal/governance \
  ./internal/runtime \
  ./internal/runtime/eino \
  ./cmd/knote
```

The inherited deterministic built-binary and real-adapter self-tests remain
mandatory defense in depth:

```sh
scripts/smoke_permissioned_binary.sh
/usr/bin/python3 tests/smoke/permissioned_graph_real_smoke.py --self-test
```

### 4. OpenFGA model and platform constituents

```sh
GOTOOLCHAIN=go1.25.12 go run github.com/openfga/cli/cmd/fga@v0.7.17 model test \
  --tests internal/authz/model/authorization.fga.yaml

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -o /tmp/knote-linux-amd64 ./cmd/knote
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -o /tmp/knote-windows-amd64.exe ./cmd/knote

GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go test -c -o /tmp/knote-identity-windows.test.exe ./internal/identity
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go test -c -o /tmp/knote-connector-windows.test.exe ./internal/connector
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go test -c -o /tmp/knote-audit-windows.test.exe ./internal/audit
```

The compiled Windows test binaries prove build coverage only. Windows file and
DACL semantics must still run on a Windows CI worker before #97 can pass.

### 5. Phase 3 real OpenFGA gate

After deterministic acceptance passes, run the #97 live entrypoint:

```sh
scripts/smoke_phase3_openfga.sh
```

The script takes no arguments. It starts the repository-pinned OpenFGA image on
a random loopback port, creates an in-memory synthetic store and model, runs
`TestPhase3OpenFGALiveSmoke`, removes the container and temporary credentials,
and prints `phase3 OpenFGA smoke passed` only on success. Exact prerequisites
and cleanup rules are in `docs/permissioned-kag-real-smoke.md`.

## Full #97 invariant-to-test matrix

| #97 invariant | Canonical fixture row | Required result | Exact canonical anchors |
|---|---|---|---|
| Two tenants with colliding external IDs cannot observe each other | `tenant-collision-isolation`, samples `2` | Cross-tenant observations `0` | `internal/connector/core_test.go#TestConnectorTenantAndOwnerIsolation`; `internal/identity/store_test.go#TestLocalStoreSCIMIsIdempotentAndTenantScoped` |
| SSO assertion and SCIM provisioning/deprovisioning are fail closed and replay safe | `identity-fail-closed-replay-safe`, samples `4` | Invalid/replayed/stale/deprovisioned accepts `0` | `internal/identity/gateway_test.go#TestGatewayBuildsTrustedAuthorizationAndFailsClosedOnIdentityChange`; `internal/identity/gateway_test.go#TestGatewayRejectsInvalidAssertionsWithoutDisclosure`; `internal/identity/publication_test.go#TestMembershipPublicationRestartRetriesUncertainWriteIdempotently`; `internal/identity/store_test.go#TestLocalStoreSCIMIsIdempotentAndTenantScoped` |
| Connector content plus ACL failure never serves | `connector-acl-failure-never-serves`, samples `2` | Partial-serving transitions `0` | `internal/connector/acceptance_test.go#TestNilPublisherCannotClaimServingAndRecoveryPublishes`; `internal/connector/processor_test.go#TestProcessorIncompleteProjectionFailsClosed` |
| Duplicate/reordered events, crashes, DLQ replay, tombstones, and full reconciliation converge | `durable-connector-convergence`, samples `7` | Replay is byte deterministic; DLQ does not advance serving; tombstones do not resurrect; residual tuple diff `0` | `internal/authz/permissioned_acceptance_test.go#TestPermissionedAcceptanceReconciliationRemovesStaleTuples`; `internal/connector/acceptance_test.go#TestSnapshotReconciliationFaultBoundariesResumeExactly`; `internal/connector/core_test.go#TestConnectorReplayAndPersistedJSONAreByteDeterministic`; `internal/connector/processor_test.go#TestProcessorCrashRecoveryAtEveryStageBoundary`; `internal/connector/processor_test.go#TestProcessorDeadLettersBoundedRetryWithoutAdvancingWatermarks`; `internal/connector/processor_test.go#TestProcessorRejectsReorderConflictsAndIdentifierReuse`; `internal/connector/processor_test.go#TestProcessorTombstoneReplayIsIdempotentAndCannotResurrect` |
| `user ∩ agent ∩ task` covers retrieval, traversal, generation, cache, citation, and session replay | `user-agent-task-intersection`, samples `4` | Incomplete-scope allows and stale protected replay `0` | `internal/authz/agent_task_test.go#TestLocalAgentTaskIntersectionCoversEveryProtectedType`; `internal/knowledge/authorized/service_test.go#TestDelegatedQueryRevalidatesCurrentScopeBeforeAuthorizationAndReuse`; `internal/runtime/eino/runner_test.go#TestRunnerBindsPermissionedInterruptForRevocationReplay`; `internal/runtime/phase3_permissioned_acceptance_test.go#TestPhase3PermissionedAcceptanceIntersectionGuardsInvocationAndResults` |
| Tool invocation and every returned resource are authorized | `tool-invocation-and-results-authorized`, samples `4` | Unauthorized callbacks and published results `0`; side effects remain separately confirmed | `internal/authz/tool_authorization_test.go#TestToolAuthorizationGateAuthorizesReturnedResourcesAtomically`; `internal/authz/tool_authorization_test.go#TestToolAuthorizationGateRevalidatesDelegationForInvocationAndReturn`; `internal/eino/tools/tools_test.go#TestAuthorizationDecoratorPreGatesBuildAndGitSideEffects`; `internal/runtime/phase3_permissioned_acceptance_test.go#TestPhase3PermissionedAcceptanceIntersectionGuardsInvocationAndResults` |
| Simulation is non-mutating and matches the policy oracle | `simulation-read-only-oracle-parity`, samples `14` | Before/after input is equal and every impact category matches the oracle | `internal/policysim/engine_test.go#TestEngineCanonicalizesAllTargetKindsWithoutMutatingInput`; `internal/policysim/engine_test.go#TestEngineClassifiesIndependentEvaluationsWithStableReasons` |
| Audit remains content free and detects tampering | `audit-content-free-tamper-evident`, samples `2` | Forbidden fields `0`; canonical chain verifies; tamper fails closed | `internal/audit/corruption_test.go#TestStoreFailsClosedOnRecordTamper`; `internal/audit/store_test.go#TestStoreAppendsCanonicalContentFreeChainAndVerifiesOnReopen` |
| Residency violations block storage and egress | `residency-blocks-storage-egress`, samples `2` | Denied callbacks and bytes `0` | `cmd/knote/permissioned_telemetry_test.go#TestPermissionedTelemetryResidencyDenialPrecedesFilesystemWrite`; `internal/residency/gate_test.go#TestOperationWrappersDenyBeforeWriteNetworkAndSubprocess` |
| Unauthorized existence, count, pagination, errors, traces, telemetry, and governance views do not leak | `unauthorized-observability-hidden`, samples `5` | Canary and unauthorized-section observations `0`; denied source calls `0` | `cmd/knote/permissioned_telemetry_test.go#TestPermissionedToolInvocationDeniedHandlerEmitsContentFreeQueryTelemetry`; `internal/governance/service_test.go#TestViewDenialDoesNotReadSource`; `internal/governance/service_test.go#TestViewProjectsAuthorizedSectionsWithoutZeroSideChannels`; `internal/runtime/permissioned_acceptance_test.go#TestPermissionedAcceptanceSideChannelSurfacesHideCanaries`; `internal/runtime/phase3_permissioned_acceptance_test.go#TestPhase3PermissionedAcceptanceIntersectionGuardsReplayWithoutSideChannels` |
| False allow is zero across the complete matrix | `false-allow-zero`, samples `14`; top-level `false_allow: 0` | Any nonzero value blocks merge | `internal/knowledge/authorized/permissioned_acceptance_test.go#TestPermissionedAcceptancePolicyOracleAndRetrievalMetrics`; `internal/knowledge/authorized/phase2_permissioned_graph_acceptance_test.go#TestPhase2PermissionedGraphPolicyOracleAcceptanceMetrics` |
| BatchCheck, connector lag, replay, reconciliation, revocation, and governance budgets are met | `operational-latency-budgets`, samples `145` | Every canonical budget below passes | The six exact budget anchors in `tests/fixtures/phase3-acceptance.json` |

Inherited files whose names contain `phase2` remain valid regression anchors;
their filenames do not make them Phase 3 aggregate evidence by themselves.

## Phase 3 performance budgets

The canonical values below come directly from
`tests/fixtures/phase3-acceptance.json`. Percentile cohorts use nearest rank;
`max` cohorts require every sample to stay within the threshold. The live smoke
reports service timing only as a diagnostic and cannot replace these budgets.

| Canonical budget ID | Metric | Cohort | Limit | Exact anchor |
|---|---|---:|---:|---|
| `batch-check-latency` | `openfga_batch_check`, P99 | `12` | `100ms` | `internal/knowledge/authorized/phase2_permissioned_graph_acceptance_test.go#TestPhase2PermissionedGraphPolicyOracleAcceptanceMetrics` |
| `connector-lag` | `connector_apply_lag`, max | `1` | `2000ms` | `internal/connector/acceptance_test.go#TestSlowConnectorCallbackDoesNotBlockAnotherTenantAndCanReadStore` |
| `governance-latency` | `governance_view`, max | `2` | `1000ms` | `internal/governance/service_test.go#TestViewAndRenderAreDeterministic` |
| `reconciliation-latency` | `full_reconciliation`, max | `1` | `1000ms` | `internal/authz/reconciliation_telemetry_test.go#TestTupleReconcilerTelemetryFailureDoesNotChangePublishedResult` |
| `replay-latency` | `session_replay`, max | `1` | `3000ms` | `internal/runtime/phase2_graph_replay_acceptance_test.go#TestPhase2GraphReplayAcceptanceRevocationClosesTraversalCacheCitationAndSession` |
| `revocation-latency` | `revocation_propagation`, P99 | `128` | `100ms` | `internal/runtime/permissioned_acceptance_test.go#TestPermissionedAcceptanceRevocationPropagationPercentiles` |

BatchCheck also has a hard physical request limit of `50`; missing, duplicate,
extra, malformed, or per-item error responses fail closed. The revocation anchor
additionally requires P95 `<= 25ms`. Connector, replay, and reconciliation must
retain their zero-lag, byte-determinism, no-resurrection, and zero-residual-diff
security invariants regardless of the latency result.

Run the existing functional and budget anchors directly with:

```sh
go test -count=1 ./internal/authz \
  -run 'TestOpenFGABatch'

go test -count=1 ./internal/connector \
  -run 'Test(ConnectorReplay|SnapshotReplay|Processor|SnapshotReconciliation|StandaloneReconciliation)'

go test -count=1 ./internal/runtime \
  -run 'TestPermissionedAcceptanceRevocationPropagationPercentiles'

go test -count=1 ./internal/governance ./internal/policysim ./internal/audit ./internal/residency

go test -count=1 ./tests/phase3 -run '^TestPhase3AcceptanceMatrix$'
```

The matrix test proves that the fixture is canonical, complete, sorted, and
bound to exact test declarations. `scripts/verify_phase3_acceptance.sh` runs the
matrix and every anchor through `go test ./...`; final measured values and the
fixture digest are recorded in the PR and issue completion comments using the
schema in `docs/phase3-release-evidence.md`.

## Quality and no-leak metrics

The inherited public-synthetic policy oracle uses `K = 4`. Positive Recall@4
and Precision@4 must each be `1.00` per principal, positive empty-result rate
must be `0`, and negative-control empty-result rate must be `1.00`. Aggregate
averages cannot hide a principal-specific failure.

Every negative fixture carries protected body, title, path, identifier, prompt,
credential, and provider-diagnostic canaries. Canaries must be absent from:

- relevance input, graph frontier, generator input, answer, citation, and cache;
- tool arguments, returned-resource envelopes, TUI/runtime events, and sessions;
- errors, traces, telemetry, governance output, audit records, and smoke output;
- persisted connector, identity, audit, and release-evidence metadata.

## Failure diagnostics

Failure output is limited to a fixed invariant slug, scenario/stage class,
sample number, expected/actual aggregate value, duration/budget class, and
content-free evidence digest. Lists are deterministic and sorted.

Do not use `set -x`, print environment variables, dump OpenFGA requests or
responses, expose provider stdout/stderr, or attach source, artifact, assertion,
connector, audit-ledger, or session bodies. A failed live smoke never justifies
weakening authorization, widening residency, skipping confirmation, or falling
back to a legacy non-permissioned path.

## Final merge gate

Issue #97 is complete only when:

1. every command required above passes at the final PR head;
2. `scripts/verify_phase3_acceptance.sh` and
   `scripts/smoke_phase3_openfga.sh` both pass and their exact-head evidence is
   recorded; the digest of `tests/fixtures/phase3-acceptance.json` is recorded;
3. every matrix row is `pass`, every budget is met, and false allow is `0`;
4. hosted CI is green on the same head;
5. a completed current-head Codex review has no verified P1/P2 finding; and
6. the PR is squash-merged to `dev`.

The durable evidence schema is maintained in
`docs/phase3-release-evidence.md`; exact-head results live in the PR and issue
completion comments. Closing #97 and epic #90 records completion of Phase 3 on
`dev`; it still does not create or publish a tag, binary release, release branch,
or GitHub Release.
