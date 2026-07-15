# Permissioned KAG Acceptance

This document defines the Phase 2 acceptance contract for issue #78 on `dev`.
It builds on the deterministic authorization, graph, reconciliation, and
protected-surface suites from issues #41 and #61, plus the real operator
composition and protected surfaces now on `dev`. The legacy
`kag.query`/`kag.explain` solver and the fake MVP TUI smoke are compatibility
surfaces, not Phase 2 production-composition evidence.

Passing this contract is evidence for the reviewed development branch. It does
not create a tag, publish artifacts, or claim a GitHub Release.

## Gate levels

| Gate | Required | Network or credentials | Purpose |
|---|---|---|---|
| Deterministic baseline | yes | none | Go/Python contracts, policy model, graph/revocation invariants, protected surfaces, and allowlist parity |
| Deterministic built binary | yes | no external network or credentials; loopback deterministic doubles only | Prove the built `cmd/knote` artifact crosses the real permissioned startup and request boundaries |
| Live OpenFGA + OpenSPG/KAG smoke | no | disposable local services | Check pinned external-service compatibility without replacing deterministic acceptance |

The baseline commands are:

```sh
KNOTE_KAG_FAKE=1 go test ./...
/usr/bin/python3 -m unittest discover -s adapters/kag -p '*test*.py'
/usr/bin/python3 tests/smoke/permissioned_graph_real_smoke.py --self-test
GOTOOLCHAIN=go1.25.12 go run github.com/openfga/cli/cmd/fga@v0.7.17 model test \
  --tests internal/authz/model/authorization.fga.yaml
```

Use Python 3.11 for the Python gates to match CI. No production OpenFGA, KAG,
model-provider, or workspace credential is permitted in deterministic
acceptance.

## Mandatory built-binary gate

Run the issue #78 deterministic entrypoint from the repository root:

```sh
scripts/smoke_permissioned_binary.sh
```

This entrypoint is mandatory locally and in CI. After building `bin/knote`, CI
invokes `scripts/smoke_permissioned_binary.sh --bin bin/knote` so the gate
exercises the exact artifact produced by the preceding build step.

The entrypoint rejects `KNOTE_KAG_FAKE` even when it is set to an empty value,
builds `cmd/knote` once with `go build -trimpath`, verifies that artifact with
`--version`, and invokes the exact artifact for every scenario. To exercise an
already-built artifact, pass `--bin /absolute/path/to/knote`; the harness does
not rebuild it.

The deterministic harness:

1. invokes the exact built artifact, with no `go run` and no direct construction
   of the Go service under test;
2. sets `KNOTE_PERMISSIONED=1`, keeps `KNOTE_KAG_FAKE` absent, and supplies the
   complete real-mode operator configuration;
3. uses only checked-in synthetic data, a local deterministic
   OpenFGA-compatible endpoint, an allowlisted local provider, and a
   deterministic model endpoint;
4. exercises `authorized_query`, `authorized_resume`,
   `permission_bound_resume`, `denied_query`, `revoked_resume`,
   `provider_failure`, and `backend_failure`;
5. proves authorization and replay rechecks, provider non-invocation after deny
   or backend failure, and no generation after provider retrieval failure;
6. asserts that denied/secret canaries and provider diagnostics never reach
   public errors, TUI events, or session history;
7. emits one sorted metadata-only JSON result. Running
   `scripts/smoke_permissioned_binary.sh --self-test` materializes the fixture
   twice and requires byte-identical artifact files and manifest digests.

The shell entrypoint delegates to
`tests/smoke/permissioned_binary_acceptance.py` and uses
`tests/fixtures/permissioned-binary/permissioned_binary_provider.py`. A
build-only step, `scripts/smoke_fake_mvp.sh`, the Python adapter self-test, or
the optional live smoke cannot stand in for this gate.

## Fixture oracle

Quality metrics use `K = 4`. Compute every rate per principal/fixture first;
aggregate reporting must not hide a principal-specific failure. Each positive
fixture has at least one authorized relevant oracle result, and each negative
control has none.

| Principal | Authorized relevant results | Expected result |
|---|---:|---|
| Alice | `2` | both relevant results returned |
| Bob | `1` | the relevant result returned |
| Unknown principal | `0` | empty negative control |

| Metric | Definition | Required result |
|---|---|---:|
| Positive Recall@4 | authorized oracle-relevant results returned in the first four / all authorized oracle-relevant results | `1.00` for Alice and Bob |
| Positive Precision@4 | authorized oracle-relevant results returned in the first four / all results returned in the first four | `1.00` for Alice and Bob |
| Positive empty-result rate | positive fixtures returning no evidence / all positive fixtures | `0` |
| Negative-control empty-result rate | negative controls returning no evidence / all negative controls | `1` |
| Policy-oracle false allows | denied oracle resources observed as allowed or returned | `0` |
| Unauthorized path participation | unauthorized resources participating in any completed or partial graph path | `0` |
| Unauthorized generator participation | unauthorized evidence or path resources passed to generation | `0` |

A positive fixture with a missing sample, zero denominator, empty result, or
extra non-relevant result in the first four fails instead of being omitted.
Negative-control emptiness is reported separately and is never averaged into
positive emptiness.

Discovery and result order is significant. Trusted discovery returns a complete,
deterministic, body-free catalog. Authorization filters it before relevance
ranking, and retrieve accepts only exact authorized handles. Tests compare those
handles, projection and authorization revisions, and generator, citation, trace,
cache, and session references. A body-free candidate with the wrong tenant,
knowledge base, authorization boundary, digest, projection, ACL revision, or
serving state is a contract failure, not an ordinary retrieval miss.

## Drop accounting

Per-hop authorization drops are a deterministic fixture diagnostic, not a
relevance-quality metric. For each hop, report candidate, allowed, and dropped
counts and require `candidates = allowed + dropped`. Across one Alice/Bob/unknown
round, the fixture requires `40` candidates, `24` allows, and `16` drops, so
`hop_authorization_drop_rate = 0.40`; over the four deterministic rounds those
counts are `160`, `96`, and `64`. These values detect fixture or authorization
stage drift and must not be generalized as a production quality threshold.

Track the final post-filter independently through
`final_filter_candidate_count`, `final_filter_allowed_count`, and
`final_filter_dropped_count`; aggregate acceptance may also report
`post_filter_drop_rate = dropped / candidates`. The policy-oracle fixture
requires `3` candidates, `3` allows, and `0` drops per round (`12/12/0` across
four rounds), with `post_filter_drop_rate = 0`. Do not fold these values into
per-hop drops, Recall@4, Precision@4, or empty-result rates. A final drop can
demonstrate the last revocation/authorization barrier; regardless of its count,
no dropped resource may reach evidence, citations, generation, cache, replay, or
protected output.

## Latency and revocation budgets

Percentiles use nearest rank: sort the complete sample set and select
`ceil(percentile * sample_count) - 1`. Missing samples fail the cohort. Report
sample count with every percentile.

| Metric | Sample boundary | Required result |
|---|---|---:|
| Local hard latency | every local deterministic authorization, retrieval, graph, and authorized-query sample | each sample `<= 1s` |
| Synthetic P99 | deterministic synthetic end-to-end query samples with fixed injected stage durations | `P99 <= 100ms` |
| Revocation propagation P95 | declared revocation through observed cache/replay protection | `P95 <= 25ms` |
| Revocation propagation P99 | same sample set | `P99 <= 100ms` |

The 1-second ceiling catches hangs and accidental external I/O; it does not
replace the 100-millisecond synthetic P99. Synthetic latency uses fixed clocks or
durations so scheduler noise cannot make it nondeterministic. Revocation uses at
least the existing 128 no-sleep samples and includes every attempt. Retries,
timeouts, malformed responses, and failures are not hidden from counts.

Physical OpenFGA `BatchCheck` requests remain bounded to
`authz.MaxBatchChecks` (`50`). Batch size, RPC count, and latency are reported as
diagnostics and must match the exact authorization stages exercised by the
fixture. A batch timeout, missing decision, duplicate correlation, wrong model,
or partial response fails closed.

## Hard security invariants

These are acceptance blockers for the code change and are never percentile
allowances:

| Invariant | Required result |
|---|---:|
| False allows | `0` |
| Unauthorized resources presented to relevance | `0` |
| Unauthorized evidence items or citations | `0` |
| Unauthorized generator/solver inputs | `0` |
| Unauthorized graph-path participation | `0` |
| Unauthorized trace/debug/audit/session participation | `0` |
| Cross-tenant candidates reaching authorization, load, expand, or generate | `0` |
| Serving projections with incomplete or failed ACL state | `0` |
| Stale cache, citation, derived-artifact, or session reads after revocation observation | `0` |

Every negative fixture includes protected body, title, path, prompt, identifier,
and secret canaries. All canaries must be absent from public errors, traces,
debug values, telemetry fields, generated output, persisted events, and captured
adapter output.

## Telemetry acceptance

`KNOTE_PERMISSIONED_TELEMETRY_PATH` is optional. Its tests must prove:

- unset means no sink and no telemetry file;
- each non-empty line is exactly one valid JSON object in the closed telemetry
  schema;
- only fixed metric-scope/event/stage/outcome/budget enums, aggregate integer
  counts, durations, rates, and percentiles are accepted;
- unknown fields, free-form diagnostics or errors, content, paths, identifiers,
  endpoints, provider output, and secrets are absent;
- `metric_scope=operational` records contain only per-operation observations;
  cohort-only Recall@4, Precision@4, positive/negative empty-result rates,
  unauthorized path/generator participation, and latency/revocation percentiles
  remain zero and must not be interpreted as measurements;
- the deterministic acceptance cohort computes those quality and percentile
  metrics independently without joining telemetry to session or evidence data;
- open, append, encode, flush, and close failures do not change an allow, deny,
  revocation, evidence, or generated result;
- neither telemetry records nor sink failures appear as TUI/model events or in
  `.knote/sessions/*.jsonl`.

Telemetry is best-effort operational evidence. It is not an authorization input,
an audit record for content access, or a reason to retry a protected operation.
Issue #78 implements this contract in `internal/telemetry` and verifies the
runtime file sink through both writable and blocked/failing paths. The built
binary harness validates allowed and denied operational records without treating
cohort-only zero placeholders as measured values.

## Invariant-to-test map

| Scenario | Status | Direct anchor |
|---|---|---|
| Real opt-in configuration, selected-bundle loader, exact mode tools, startup context | existing | `cmd/knote/eino_test.go`; `cmd/knote/permissioned_revision_test.go`; `internal/knowledge/authorized/bundle_loader_test.go` |
| Recall@4/Precision@4, positive/negative empty controls, path participation, hop/final drops, synthetic query P99 | implemented by #78 | `internal/knowledge/authorized/phase2_permissioned_graph_acceptance_test.go: TestPhase2PermissionedGraphPolicyOracleAcceptanceMetrics`; `internal/knowledge/authorized/traversal.go: TraversalReport` |
| Hidden Claim, denied intermediate, alternate support, derivation and traversal limits | existing | `internal/knowledge/authorized/phase2_permissioned_graph_acceptance_test.go: TestPhase2PermissionedGraphDerivationBudgetsAndFailures` |
| Revocation closes traversal, cache, citation, and replay within P95/P99 | existing | `internal/knowledge/authorized/phase2_permissioned_graph_acceptance_test.go: TestPhase2PermissionedGraphCacheCitationRevocationAndSessionReplay`, `TestPhase2PermissionedGraphRevocationLatencyBudget`; `internal/runtime/phase2_graph_replay_acceptance_test.go` |
| Mixed-visibility count/exists/autocomplete/pagination/error/trace/debug/audit surfaces | existing | `internal/runtime/permissioned_acceptance_test.go: TestPermissionedAcceptanceSideChannelSurfacesHideCanaries`; `internal/runtime/phase2_protected_surfaces_acceptance_test.go` |
| Cross-tenant input stops before search, graph, or generation | existing | `internal/runtime/phase2_protected_surfaces_acceptance_test.go: TestPhase2ProtectedSurfacesAcceptanceCrossTenantStopsBeforeSearchGraphAndGenerate` |
| Full replacement removes stale content, bindings, Claims, and tuples | existing | `internal/catalog/phase2_full_reconciliation_acceptance_test.go`; `internal/authz/phase2_full_reconciliation_acceptance_test.go` |
| Go/Python predicate and resource-kind allowlists stay identical | added by #78 | `tests/fixtures/permissioned-plan-contract.json`; `internal/protocol/permissioned_plan_contract_parity_test.go`; `adapters/kag/test_permissioned_plan_contract_parity.py` |
| Content-free telemetry schema and sink-failure isolation | implemented by #78 | `internal/telemetry`; `cmd/knote/permissioned_telemetry.go`; `internal/knowledge/authorized/phase2_permissioned_graph_telemetry_test.go`; `internal/authz/reconciliation_telemetry_test.go`; built-binary coverage |
| Real composition through allow, explain, deny, empty result, revocation-aware replay, telemetry sink failure, provider failure, and backend failure | implemented by #78 and invoked by CI | `.github/workflows/ci.yml`; `scripts/smoke_permissioned_binary.sh`; `tests/smoke/permissioned_binary_acceptance.py`; `tests/fixtures/permissioned-binary/permissioned_binary_provider.py` |

Component tests remain defense in depth; all implemented rows name concrete
paths and the built-binary gate remains authoritative over its runtime scenarios.

## Failure diagnostics

Acceptance output identifies only a fixed invariant slug, scenario/stage class,
sample number, aggregate expected/actual value, and duration/budget class. Lists
and records are deterministic and sorted. Public authorization timeout,
unavailable, malformed, stale-revision, and provider failures remain generic.

Do not use `set -x`, print environment variables, dump OpenFGA requests or
responses, expose provider stdout/stderr, or include source/artifact/session
bodies in a failure report. A telemetry sink problem is diagnosed through file
existence, ownership, permissions, and free space outside the TUI; it never
changes the protected test oracle.

## Optional live counterpart

After both mandatory deterministic gates pass, an operator may run the pinned
public-synthetic OpenFGA + OpenSPG/KAG procedure in
`docs/permissioned-kag-real-smoke.md`. Its service compatibility evidence is
useful, but a skip or unavailable Docker environment does not weaken the
deterministic security gate, and a live pass does not compensate for a missing
built-binary pass.
