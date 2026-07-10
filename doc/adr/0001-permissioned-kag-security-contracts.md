# ADR 0001: Permissioned KAG Security Contracts

- Status: accepted
- Date: 2026-07-10
- Parent: GitHub issue #34
- Implements: GitHub issue #35

## Context

The existing query boundary accepts only a question string. The complete OpenSPG/KAG solver can retrieve, expand, report, summarize, and invoke an LLM before knote receives its final answer. Existing `PermissionRequest` and `ConfirmRequest` values protect local side effects; they do not authorize access to knowledge resources. Artifacts use content-derived identities, sessions replay raw events, and query failures may fall back to local summaries.

Permissioned KAG requires authorization before protected content participates in retrieval, graph expansion, generation, citations, caches, traces, or session replay.

## Decision

### Trusted authorization context

Every protected read uses an immutable `AuthorizationContext` created by a trusted runtime or API boundary. It is never accepted from LLM-controlled tool JSON. The context binds tenant, knowledge base, principal, session, request, authorization model, identity and ACL watermarks, consistency, and optional agent/task scope. Agent and task scope may narrow access but never broaden it.

Missing, malformed, stale, timed-out, partial, or indeterminate authorization information fails closed. Policy denial and hidden-resource absence are externally indistinguishable.

Fallback is allowed only when it reads the current serving projection, returns resource handles, and passes the same authorization and final-evidence checks. If no authorized fallback is available, the request returns no answer.

### Resource identity and versions

`ResourceID` is an opaque, tenant-scoped identity derived from stable source identity, never content. Source, content, ACL, index, graph, and projection versions are independent. Updating content or ACLs must not create a new canonical resource.

Document is the Phase 1 ACL boundary. Chunk inherits its Document and every Chunk decision carries the exact parent Document handle used as the authorization resource; a Chunk-scoped authorization object is invalid. Entity existence requires at least one authorized support. Claim authorization is independent from Entity visibility. A denied Claim or frontier item cannot participate in a later graph hop.

### Provenance and derived knowledge

Every evidence item carries explicit provenance. In `any_support`, each listed support must independently and completely justify the result. Otherwise the result uses source-scoped claims or `all_required`. Derived artifacts default to `all_required`.

An `EvidencePackage` contains only authorized resources and binds its decisions, citations, model ID, identity and ACL watermarks, consistency preference, projection, and visibility fingerprint to the originating request. An allow decision covers one exact `ResourceHandle`, including every mutable version, rather than every version sharing the same stable `ResourceID`. Denied titles, paths, bodies, and graph structure are never included.

### KAG execution boundary

The OpenSPG/KAG v0.8.0 complete solver is not an authorized query boundary. Post-filtering its final answer is prohibited because protected content may already have affected solver memory, traces, reports, or generation. Phase 1 keeps KAG as builder/storage and, where proven safe, a provider of controlled low-level ID-only primitives. Go owns authorization orchestration and final evidence checks.

### Git and local storage

One knote repository is one security domain. Repository and filesystem readers are trusted members of that domain, so `sources`, `artifacts`, and `evals` may remain versioned. A repository must not mix plaintext from different security domains. This boundary is not a substitute for authorization in query, citation, cache, or replay paths.

Sessions, caches, traces, evals, metrics, errors, and audit records inherit the same boundary. They may store authorized handles and version metadata, but must not store denied titles, paths, bodies, prompts, or graph structure. Legacy session events without evidence bindings are not trusted for replay.

### Terminology

Existing side-effect permission prompts are canonically `ActionApproval` and `ActionConfirmation`. `Authorization` is reserved for resource access decisions. Legacy Go names and serialized fields remain compatible during migration.

### Revocation

Revocation affects future query, graph participation, cache hits, citation access, and session replay after the declared consistency boundary. It cannot retract content already displayed, copied, or sent to an external model.

## Consequences

- Query, explain, eval, citation, and replay contracts will consume trusted authorization context in later issues.
- OpenFGA decisions must pin an authorization model ID and treat incomplete batch results as deny.
- KAG query/explain cannot remain the secure production path unless issue #36 proves interception before every observable or reasoning step.
- Stable IDs and versioned serving projections are required before authorized retrieval can ship.
- Existing unbound sessions and artifacts remain legacy records; they are not silently upgraded or replayed as authorized content.

## Non-goals

This ADR does not run OpenFGA, change the current runtime path, implement retrieval filtering, add multi-hop production graph traversal, provide SSO/SCIM, or support cross-organization sharing.
