# Permissioned KAG Acceptance

This document defines the deterministic Phase 1 release gate for issue #41. It
tests the security contracts in `doc/adr/0001-permissioned-kag-security-contracts.md`
and the interception boundary in `doc/adr/0002-kag-query-interception.md`. It does
not turn the legacy real KAG solver into a permissioned query path.

## CI entry points

The credential-free gate is the same command run by `.github/workflows/ci.yml`:

```sh
KNOTE_KAG_FAKE=1 go test ./...
/usr/bin/python3 -m unittest discover -s adapters/kag -p '*test*.py'
GOTOOLCHAIN=go1.25.12 go run github.com/openfga/cli/cmd/fga@v0.7.17 model test --tests internal/authz/model/authorization.fga.yaml
```

For a focused local pass:

```sh
KNOTE_KAG_FAKE=1 go test -count=1 ./internal/authz ./internal/catalog ./internal/knowledge/authorized/... ./internal/knowledge/kag ./internal/protocol ./internal/runtime ./tests/eino_tools
python3 -m unittest discover -s adapters/kag -p '*test*.py'
```

No OpenFGA, OpenSPG, KAG, or model-provider credential is permitted in this
gate. Fixtures, clocks, candidate order, authorization decisions, and expected
paths must be fixed. Failure output may contain opaque resource IDs and version
metadata, but not protected bodies, titles, paths, prompts, or relation labels.

## Fixture oracle

Use `K = 3` for the Phase 1 positive-query cohort. The shared candidate list is
the three deterministic resources in
`internal/knowledge/authorized/fixture/fixture.go`:

| Principal | Authorized relevant resources | Expected denied candidates | Expected empty result |
|---|---:|---:|---:|
| Alice | 2 | 1 | no |
| Bob | 1 | 2 | no |
| Unknown principal | 0 | 3 | yes |

Discovery and result order is significant. The trusted adapter must return a
complete, deterministic, body-free resource catalog. Authorization filters that
catalog before a relevance provider runs, and `Retrieve` accepts only the exact
sorted authorized handles. A test must compare those handles, exact projection
and authorization versions, and the full set of generator, citation, trace,
cache, and session references. A body-free candidate with the wrong tenant,
knowledge base, authorization boundary, content digest, projection, ACL version,
or serving state is a contract failure, not an ordinary retrieval miss.

## Hard invariants

The following are release blockers and are not percentile metrics:

| Invariant | Required result |
|---|---:|
| Policy-oracle false allows | 0 |
| Unauthorized resources presented to the relevance provider | 0 |
| Unauthorized evidence items or citations | 0 |
| Unauthorized generator or solver inputs | 0 |
| Unauthorized trace/debug resource participation | 0 |
| Unauthorized graph-path participation | 0 |
| Serving projections with incomplete or failed ACL state | 0 |
| Stale cache, citation, or session reads after revocation observation | 0 |
| Cross-tenant candidates reaching authorization, load, expand, or generate | 0 |

Every negative fixture must also assert that the protected canary body is absent
from errors, traces, debug values, metrics labels, generated output, persisted
events, and adapter stdout/stderr captured by the test.

## Metric definitions and budgets

All rates are computed per principal first; aggregate reporting must not hide a
principal-specific failure. Percentiles use nearest rank: sort the complete
sample set and select `ceil(percentile * sample_count) - 1`. A missing sample or
zero denominator fails the positive cohort instead of being omitted. The strict
revocation test uses 128 no-sleep samples; BatchCheck and retrieval tests report
P99 over their deterministic scenario samples and enforce the hard ceiling on
every sample.

| Metric | Definition | CI budget |
|---|---|---:|
| Authorized Recall@3 | returned authorized relevant / oracle authorized relevant | 1.00 for Alice and Bob |
| Authorized Precision@3 | returned authorized relevant / all returned evidence | 1.00 for every non-empty result |
| Authorization drop rate | denied handles / valid handles returned by trusted discovery or graph expansion | exactly 1/3 for Alice and 2/3 for Bob; aggregate exactly 0.50 |
| Authorized empty-result rate | positive queries with no authorized evidence / positive queries | 0/2; the unknown-principal negative control is exactly 1/1 |
| Authorized Path Completeness | complete authorized oracle paths returned / complete authorized oracle paths | 1.00 for controlled provenance fixtures |
| BatchCheck size | checks in one `BatchCheckRequest` | 1 to `authz.MaxBatchChecks` (50) |
| BatchCheck RPC count | sum of authorization batches for one query | exactly 2 for the no-expansion Alice/Bob fixture; exactly 5 for a complete one-hop fixture when each stage has at most 50 unique objects |
| BatchCheck latency | elapsed time for one deterministic local batch | every sample <= 1 s; report P99 |
| Retrieval latency | fake `Retrieve` call elapsed time | every sample <= 1 s; report P99 |
| Total authorized query latency | `Service.Query` entry through validated generation result, including authorization and exact load | every sample <= 1 s; report P99 |
| Revocation propagation | `RevocationRequest.RevokedAt` through cache tombstone `ObservedAt` | P95 <= 25 ms and P99 <= 100 ms across 128 no-sleep samples |
| Content/ACL terminal skew | content projector terminal time to ACL projector terminal time for the same projection | maximum <= 25 ms in the controlled-clock fixture |
| Unauthorized serving skew | time an incomplete or ACL-failed projection is serving | exactly 0 ms |

The BatchCheck count formula for larger fixtures is:

```text
ceil(unique_discovered_objects / 50)      # pre-ranking authorization
+ ceil(unique_start_objects / 50)         # zero when traversal is disabled
+ ceil(unique_claim_objects / 50)         # zero when traversal is disabled
+ ceil(unique_object_objects / 50)        # zero when traversal is disabled
+ ceil(unique_final_path_and_evidence_objects / 50)
```

Cache-hit revalidation permits two live authorization passes; each pass uses as
many 50-item physical batches as its exact resource set requires. Citation open
and protected-session replay use the same physical batch ceiling. Revocation
application permits one live pass after synchronous tombstoning. Count every
attempt, including a timeout or malformed response; retries are not hidden from
the metric.

Latency tests run only against in-process deterministic doubles or the fake
adapter and use monotonic elapsed time. They must not contact a network service.
`TestPermissionedAcceptanceRevocationSLO` also applies a secondary 1-second
P95/P99 ceiling over 16 complete query/cache/citation samples. The content/ACL
test uses a controlled clock in its harness; public artifact formats do not gain
test-only timestamps. An ACL failure ends the skew sample at the failure
observation and must leave the projection non-serving.

## Invariant-to-test map

The issue #41 acceptance files are credential-free and run under `go test ./...`.
The older component tests remain defense in depth, but these are the direct
scenario gates:

| Issue #41 scenario | Current deterministic anchors |
|---|---|
| Alice and Bob receive different evidence; pre-ranking authorization, quality, and drop/empty budgets | `internal/knowledge/authorized/service_test.go: TestQueryScopesEvidencePerPrincipal`; `internal/runtime/permissioned_acceptance_test.go: TestPermissionedAcceptanceSideChannelSurfacesHideCanaries`; `internal/knowledge/authorized/permissioned_acceptance_test.go: TestPermissionedAcceptancePolicyOracleAndRetrievalMetrics` |
| Entity support and Claim visibility remain independent | `internal/knowledge/authorized/permissioned_acceptance_test.go: TestPermissionedAcceptanceVisibleEntityHiddenClaim`; `internal/authz/permissioned_acceptance_test.go: TestPermissionedAcceptanceEntityVisibleProtectedClaimHidden` |
| A denied intermediate blocks later participation; `any_support` and `all_required` stay closed | `internal/knowledge/authorized/permissioned_acceptance_test.go: TestPermissionedAcceptanceProvenancePathSemantics`; `internal/authz/permissioned_acceptance_test.go: TestPermissionedAcceptanceDeniedIntermediateClaimBlocksPathParticipation`; `internal/catalog/permissioned_acceptance_test.go: TestPermissionedAcceptanceProvenanceModesAndIntermediateRevocation` |
| Revocation denies cache, in-flight result, citation, and replay within SLO | `internal/knowledge/authorized/permissioned_acceptance_test.go: TestPermissionedAcceptanceRevocationSLO`; `internal/runtime/permissioned_acceptance_test.go: TestPermissionedAcceptanceRevocationDeniesCacheCitationAndSessionReplay`, `TestPermissionedAcceptanceRevocationPropagationPercentiles` |
| Content success plus ACL failure is non-serving and skew-bounded | `internal/catalog/permissioned_acceptance_test.go: TestPermissionedAcceptanceContentSuccessACLFailureNeverServes` |
| Timeout or partial authorization fails closed | `internal/knowledge/authorized/permissioned_acceptance_test.go: TestPermissionedAcceptanceAuthorizationFailuresFailClosed`; malformed/extra/wrong-model cases remain anchored in `internal/authz/openfga_test.go` |
| Count, exists, autocomplete, pagination, errors, traces, debug, and status hide canaries | `internal/runtime/permissioned_acceptance_test.go: TestPermissionedAcceptanceSideChannelSurfacesHideCanaries`, `TestPermissionedAcceptanceProtectedReplayFailsClosed` |
| Cross-tenant candidates stop before authorization, content, or generation | `internal/knowledge/authorized/permissioned_acceptance_test.go: TestPermissionedAcceptanceCrossTenantStopsBeforeContentBoundaries` |
| Reconciliation removes stale content and tuples | `internal/catalog/permissioned_acceptance_test.go: TestPermissionedAcceptanceReconciliationRemovesStaleContent`; `internal/authz/permissioned_acceptance_test.go: TestPermissionedAcceptanceReconciliationRemovesStaleTuples` |

`count`, `exists`, `autocomplete`, and pagination are not exposed by the current
permissioned primitive or CLI surface. Their Phase 1 assertion is therefore
surface closure: unknown methods and unknown response fields fail, and denied
resource existence is indistinguishable from absence. Any future endpoint must
add a policy-oracle and canary test before it is exposed.

## Failure diagnostics

Acceptance failures identify the invariant and version boundary without
including content. Knowledge/runtime tests use `projection` and `authz_model`
(`authz` is an accepted short form); catalog tests use `projection_version` and
`authz_version`:

```text
invariant=<slug> projection=<version> authz_model=<id>:
sample=<n> expected=<metadata-only value> actual=<metadata-only value>
```

Lists are sorted by resource ID. Authorization timeouts and malformed responses
must report the generic fail-closed class at the public boundary; detailed
transport errors remain test-local.

## Phase 2-only gaps

Passing this Phase 1 suite does **not** prove authorization-aware production
graph reasoning:

- `internal/knowledge/authorized/fixture/fixture.go` sets `ExpandLimit: 0` and
  uses a document-only authorization boundary.
- Real `kag.retrieve`, `kag.expand`, and `kag.generate` return
  `unsupported_primitive` before KAG setup. The legacy real `kag.query` and
  `kag.explain` paths are not permissioned acceptance evidence.
- Controlled one-hop handle tests prove authorization ordering, not arbitrary
  Claim traversal, multi-hop path completeness, a restricted graph DSL, or
  graph-query time/width/depth limits.
- Timing-resistant count/exists/autocomplete/pagination behavior, dynamic
  all-required graph derivations, and production graph path metrics remain
  Phase 2 work from issue #34.

Issue #41 is a gate for creating that work. Its report must label these metrics
`not_applicable_phase_1`, never zero or passing.
