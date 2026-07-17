# ADR 0005: Enterprise Control and Data Plane Contracts

- Status: accepted
- Date: 2026-07-17
- Parent: GitHub issue #90
- Implements: GitHub issue #91

## Context

Phase 2 established authorization before retrieval and graph expansion, immutable projection publication, exact evidence binding, revocation-aware caches and citations, and session authorization envelopes. Those mechanisms are scoped to one configured security domain. Phase 3 adds enterprise identity, connectors, durable change processing, agent and task delegation, tool authorization, governance, audit, and residency.

These features cannot be added as unrelated adapters. Their identifiers, watermarks, replay rules, tenant ownership, and failure behavior must agree before provider-specific implementations exist. Otherwise a content event can outrun its ACL, an identity can collide across tenants, a replay can resurrect a tombstoned resource, or a tool can return content outside its invocation scope.

## Decision

### Tenant is the root partition

Every Phase 3 control-plane record carries an explicit version and tenant ID. Tenant identity is obtained only from a trusted gateway or operator configuration. It is never accepted from a prompt, model output, tool argument, connector body, or resumable session payload.

Tenant-scoped identifiers are opaque and canonical. The same external SSO subject, connector key, agent ID, task ID, or source key in two tenants represents two different objects. Lookups, indexes, checkpoints, serving pointers, DLQs, audit chains, and caches are physically or cryptographically partitioned by tenant before later authorization checks run.

Cross-tenant input fails closed. Hidden-resource absence and authorization denial remain externally indistinguishable.

### Control plane and protected data plane are separate

The control plane may persist content-free metadata:

- tenant and residency configuration;
- normalized identity and group references;
- connector registrations, event envelopes, receipts, checkpoints, and error codes;
- authorization model, identity, ACL, delegation, and policy watermarks;
- opaque resource handles, decision references, and audit digests;
- simulation and impact references authorized for an operator.

The protected data plane owns source bodies, chunks, claim text, graph predicates, prompts, generated answers, and connector payloads. A control-plane record contains a digest and opaque handle, not a protected body. Credentials, bearer assertions, refresh tokens, connector secrets, and encryption keys are absent from both public protocol artifacts and telemetry.

One Git repository remains one security domain. Phase 3 does not put plaintext from multiple ACL domains into shared Git history.

### Trusted identity snapshots

SSO and SCIM providers are normalized into a versioned `IdentitySnapshot` after issuer, audience, subject, tenant, expiry, and replay checks. The public snapshot contains provider and subject references, principal and sorted group IDs, state, one identity watermark, and a bounded validity interval. Raw assertions are not persisted in the protocol record.

Identity snapshots are immutable. Provisioning, group membership changes, and deprovisioning create a new authoritative watermark. Authorization contexts pinned to an older identity watermark are stale and fail closed according to the requested consistency boundary.

### Durable connector change contract

A connector emits a tenant-scoped, monotonically sequenced `ConnectorEventEnvelope` with an event ID, idempotency key, kind, source and ACL watermarks, opaque resource ID where applicable, payload digest, and UTC occurrence time. A deterministic event fingerprint binds every envelope field; checkpoints, receipts, and tombstones record that fingerprint so reused identifiers cannot disguise changed metadata.

The durable event pipeline follows these rules:

1. Append the event durably before application.
2. Apply by deterministic idempotency key.
3. Persist operation receipts before advancing the connector checkpoint.
4. Advance the checkpoint only after all required content, ACL, catalog, graph, index, tuple, cache, citation, and session invalidation work succeeds.
5. Move bounded-retry poison events to a tenant-scoped DLQ without advancing the serving or connector watermark.
6. Accept an exact replay of the committed event as a no-op; otherwise accept only the immediately following sequence and reject conflicts, gaps, or stale events.
7. Represent deletes and revocations as explicit tombstones.
8. Use authoritative snapshot completion to drive full reconciliation and stale-state removal.

Content success plus missing or failed ACL application never becomes serving. A partially applied projection remains non-serving, including after restart.

### Agent and task intersection

When an agent acts for a user on a task, all three identities are mandatory and the effective scope is:

```text
user permission AND agent delegation AND task assignment
```

`AgentTaskScope` binds tenant, knowledge base, principal, agent, task, authorization model, identity watermark, ACL watermark, delegation watermark, issue time, and expiry. It must exactly match the trusted `AuthorizationContext`. Any missing, expired, revoked, stale, or mismatched component denies retrieval, traversal, generation, citation, cache use, and session replay.

The scope fingerprint is deterministic and includes every mutable authorization input. It can key caches and audit references but cannot replace a current high-risk authorization check.

### Tool authorization has two gates

Tool execution uses two independent authorization stages:

1. authorize the invocation before the tool reads protected state or performs a side effect;
2. authorize each returned resource before it enters an event, TUI message, trace, citation, cache, session, or model input.

Action confirmation remains separate. A side-effecting tool must pass resource/action authorization and then receive explicit confirmation. Confirmation never grants data access.

Tool result contracts contain sorted exact `ResourceHandle` values only. Protected bodies use `EvidencePackage` or another exact authorization-bound content container. Unregistered tools, unknown actions, malformed obligations, mixed-tenant results, partial decisions, and indeterminate responses fail closed.

### Policy simulation and impact analysis are read only

Simulation requests pin base and proposed authorization model, identity, and ACL watermarks. The only protocol mode is `read_only`. Simulation cannot update serving tuples, identities, projections, pointers, connector checkpoints, sessions, caches, or policy watermarks.

Impact reports are deterministic, sorted, tenant-scoped records of grant, revoke, unchanged, or indeterminate transitions. The governance layer must authorize access to object existence and counts before rendering an impact report.

### Audit is content free and tamper evident

The protocol audit reference includes tenant, actor reference, action, outcome, correlation ID, previous digest, record digest, and UTC time. It deliberately has no prompt, title, path, resource body, assertion, credential, graph structure, or generated answer field.

The audit implementation will maintain one append-only hash chain per tenant and verify it on read. A broken link, duplicate record ID, missing predecessor, or cross-tenant predecessor is an integrity failure, not a warning.

### Residency is checked before persistence or egress

A tenant has one home region and sorted allowlists for storage, processing, and egress. Every protected-content, identity, ACL, audit, telemetry, and backup operation is checked against the exact policy watermark before bytes are persisted, processed, or sent.

An empty egress list means deny all egress. Unknown region, operation, data class, tenant, or policy watermark fails closed. Residency checks do not replace resource authorization; both must allow.

### Determinism and versioning

Phase 3 protocol records use structs and sorted slices rather than maps for security-relevant serialization. IDs, groups, regions, resources, and impact entries are unique and canonical. Timestamps are UTC. Event sequence numbers begin at one because an absent checkpoint represents the initial state.

Contract versions evolve independently from provider implementations. Unknown versions are rejected. New optional fields may not silently weaken tenant, watermark, scope, or digest binding.

## Ownership boundaries

- `internal/protocol` owns the stable records and fail-closed structural validation.
- the trusted identity package will own assertion verification, SCIM normalization, tenant identity storage, and authorization-context construction;
- the connector package will own outbox/CDC durability, receipts, checkpoints, DLQ, tombstones, and reconciliation orchestration;
- `internal/authz` will own agent/task and tool policy checks and OpenFGA model evolution;
- `internal/runtime` and `internal/eino/tools` will own invocation gating and returned-resource enforcement;
- the governance and telemetry layers will own simulation, impact, audit, residency enforcement, and Bubble Tea projection;
- `internal/catalog` remains authoritative for resource/provenance metadata and immutable serving projections;
- OpenFGA remains authoritative for authorization relationships and decisions;
- KAG remains behind the controlled primitive boundary and never becomes a source of identity or authorization truth.

## Consequences

- Provider-specific work can proceed in parallel after this contract slice without inventing incompatible tenant or replay semantics.
- Durable metadata stores must provide atomic append, fsync, restart recovery, and tenant partitioning.
- Full reconciliation must coordinate more systems than Phase 2 while retaining one fail-closed serving decision.
- Agent, task, tool, simulation, audit, and residency checks add latency and therefore require explicit acceptance budgets.
- Existing Phase 2 records remain valid inside their configured security domain. They are not implicitly promoted to multi-tenant enterprise records.

## Rejected alternatives

### Trust tenant or identity fields supplied by tools

Rejected because model-controlled input could select a different tenant or principal.

### Let connectors update content and ACL state independently in serving storage

Rejected because content can become visible before the corresponding ACL or revocation is applied.

### Use at-least-once delivery without idempotency and tombstones

Rejected because retries can duplicate state and stale replays can resurrect deleted resources.

### Treat action confirmation as tool authorization

Rejected because a user confirming a side effect does not prove that the user, agent, or task may access the target data.

### Store protected details in audit and governance records

Rejected because audit, telemetry, and operator surfaces become alternate disclosure paths.

### Add a separate web governance stack

Rejected for this phase. The operator surface remains Go/Bubble Tea so knote keeps a single Go binary and one runtime permission model.

## Follow-up issues

- #92 implements trusted identity, SSO/SCIM, and tenant isolation.
- #93 implements connector ACL sync and durable event processing.
- #94 implements the user-agent-task intersection.
- #95 implements tool invocation and return authorization.
- #96 implements simulation, audit, residency, and governance TUI.
- #97 proves Phase 3 end to end.
