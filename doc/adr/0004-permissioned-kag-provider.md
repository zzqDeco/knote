# ADR 0004: Permissioned KAG Primitive Provider

- Status: accepted
- Date: 2026-07-14
- Parent: GitHub issue #55
- Implements: GitHub issue #57
- Depends on: ADR 0003

## Decision

Real permissioned primitives use an operator-configured, knote-owned provider
behind the Python adapter. The provider is selected with
`KNOTE_KAG_PERMISSIONED_PROVIDER=module:factory`; the Go client can set the same
value through `Client.PermissionedProvider`.

The adapter validates the complete request and the immutable current graph
bundle before importing the module or invoking its factory. Provider stdout and
stderr are discarded. Provider exceptions and malformed responses become
generic typed errors and are never echoed.

Stock OpenSPG/KAG `SearchApiABC`, `GraphApiABC`, solver pipelines, fuzzy graph
selection, PPR, retrieval summaries, raw DSL, and legacy `kag.query` or
`kag.explain` are not part of this boundary. Current KAG search and graph APIs
materialize complete index/entity fields, so they cannot satisfy the
pre-authorization body-free contract.

## Provider Contract

The factory receives a body-free context containing only the workspace,
tenant, knowledge base, selected projection version, and operator configuration
locations. It may initialize external search and generation components only at
that point.

`retrieve(request)` receives:

```json
{
  "version": 1,
  "query": "question",
  "limit": 10,
  "projection_version": "prj_..."
}
```

It returns exactly:

```json
{
  "candidates": [
    {"graph_object_id": "kg_...", "score": 0.9}
  ]
}
```

The adapter rejects unknown fields, duplicate or foreign graph IDs, invalid
scores, and excess candidates. It maps accepted IDs back to exact serving
handles from `graph_bindings.jsonl`; the provider cannot supply resource
metadata.

`generate(request)` receives only the already-authorized, digest-verified exact
evidence set and returns exactly `{"answer":"..."}`. The adapter constructs
citations, evidence IDs, and trace IDs from the original validated evidence.
Provider input is deep-copied, so in-place mutation cannot widen those sets.

`expand` does not call an external graph API. It traverses the verified
`claim_bindings.jsonl` one structural hop at a time:

1. an authorized subject entity yields its body-free Claim handle;
2. an authorized Claim yields its body-free object handle.

This creates the authorization point required between Claim and target. No
predicate label, source body, path text, or property is emitted.

## Failure Contract

- Missing provider or capability: `primitive_unavailable`.
- Malformed, foreign, content-bearing, or oversized provider output:
  `invalid_primitive_response`.
- Missing or inconsistent immutable graph bindings: `invalid_graph_binding`.
- Malformed request or evidence: `invalid_request`.
- Go cancellation or deadline terminates the adapter process and remains the
  authoritative returned error.

All real results declare `mode: real`. Legacy solver methods remain available
only for explicit non-permissioned compatibility smoke and are never a fallback
for these primitives.
