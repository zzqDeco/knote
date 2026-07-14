# ADR 0003: Permission-Safe Graph Identity and Projection

- Status: accepted
- Date: 2026-07-14
- Parent: GitHub issue #55
- Implements: GitHub issues #56 and #58
- Inspected package: OpenSPG/KAG `0.8.0`

## Decision

OpenSPG/KAG remains a builder integration, but its search and graph APIs are a **No-Go** as the serving permissioned graph store. Knote will serve retrieval and traversal from a knote-owned, immutable projection whose only pre-authorization values are opaque graph IDs and exact `protocol.ResourceHandle` values.

The selected artifact bundle is the sole identity authority. Flat compatibility exports, KAG corpus record IDs, OpenSPG node IDs, labels, descriptions, snippets, relation properties, solver traces, and caller-provided DSL are never accepted as serving bindings.

Every new bundle declares `graph_binding_contract_version: 1` and contains:

- `graph_bindings.jsonl`: one projection-scoped `kg_...` ID mapped to one exact serving resource handle;
- `claim_bindings.jsonl`: source-backed Claim triples represented only by opaque graph IDs and an opaque `pred_...` predicate key.

Older v2 bundles without a declared graph binding contract remain readable for compatibility, but real permissioned primitives fail closed when the declaration or either file is absent.

## Go/No-Go Result

KAG `SearchApiABC` and `GraphApiABC` do not document a supported guarantee that a caller-supplied corpus record ID becomes the exact identifier returned by all search and graph operations. Stock one-hop graph access can materialize entity descriptions, relation properties, and free-form labels before knote can authorize them. Raw `execute_dsl` also permits unrestricted labels and properties.

Therefore no OpenSPG/KAG result identifier is currently trusted. A later integration may use the same binding contract only after it proves that the returned identifier is the exact knote-issued `kg_...` value and that no other candidate metadata is materialized. Until then, issues #57-#60 must use the knote-owned projection.

## Identity Contract

`GraphObjectID` is deterministic for exactly:

```text
graph_binding_contract_version + NUL + projection_version + NUL + resource_id
```

The public value is the first 128 bits of the SHA-256 digest with a `kg_` prefix. It reveals neither the Catalog resource ID nor content. The binding contains the full exact serving handle, including tenant, knowledge base, authorization object, authorization resource, content digest, source/content/ACL/index/graph/projection versions, resource type, and serving state.

All bindings in one file must:

- belong to one tenant and knowledge base;
- share source, ACL, index, graph, and projection versions;
- be unique by both graph ID and resource ID;
- be sorted by graph ID;
- contain no paths, titles, snippets, text, labels, descriptions, or properties.

The Python adapter independently verifies `current.json`, the manifest digest, graph contract version, sorted file descriptors, file digest, file size, JSONL count, exact fields, scope, and versions before a real primitive can emit a result.

## Claim Triple Contract

A `ClaimTripleBinding` contains:

```text
claim kg ID
subject entity kg ID
opaque predicate key
object entity kg ID
source document kg ID
derivation mode
sorted provenance document/chunk kg IDs
```

The predicate key is a `pred_...` digest, not a relation label. The Claim remains independently authorizable; its provenance must resolve to the declared source document or chunks whose authorization boundary is that document. Catalog Claim records explicitly distinguish `unbound` Phase 1 text claims from `source_backed` semantic claims. Unbound claims remain in `claims.jsonl` for compatibility but produce neither graph Claim resources nor `ClaimTripleBinding` records.

## Generic Graph Schema

The permissioned store has exactly two structural types:

- `KnoteResource(graph_object_id)`
- `KnoteClaimEdge(claim, subject, predicate_key, object, source_document, provenance)`

Tenant, knowledge base, projection, labels, and property names are not query parameters. The future restricted DSL compiles to lookups over these fixed fields and the already-selected bundle. It cannot name an OpenSPG label, property, namespace, tenant, knowledge base, or projection.

## Lifecycle and Publication

1. A build derives all graph bindings from Catalog resources after they become a complete staged projection.
2. The immutable files and their descriptors are staged and digest-verified with the rest of the bundle.
3. Catalog projection publication succeeds before `artifacts/current.json` advances.
4. Readers use only the bundle selected by the verified current pointer.
5. Revoked, tombstoned, superseded, failed, or incomplete resources cannot produce a serving handle or graph binding.
6. Projection cutover replaces the complete graph namespace; graph IDs change because projection version is part of their identity.
7. Replay with the same source snapshot, ACL/build configuration, and projection version produces byte-identical bindings.
8. Reconciliation is full: omitted resources and claims disappear with the old immutable bundle. No incremental OpenSPG state is authoritative.
9. If artifact pointer publication fails before commit, the exact candidate-owned Catalog pointer is rolled back to its base and the unselected Catalog candidate is removed before retry.

## Consequences

- Issue #57 can implement real permissioned primitives without trusting OpenSPG result metadata.
- Issue #58 owns semantic Claim extraction and restricted graph compilation.
- Issue #59 can enforce authorization between bounded hops because every frontier value resolves to an exact serving handle.
- Compatibility exports remain useful for inspection and Git diffs, but the adapter never reads them as authority.
- KAG build and legacy query smoke remain separate from permissioned primitive acceptance.
