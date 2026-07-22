# Permissioned KAG Operations

This guide applies to the opt-in real permissioned composition on `dev`. It
documents the Phase 3 operator and security contract validated by issue #97,
including identity, connector, agent/task, tool, governance, audit, and
residency boundaries. Deterministic fixture mode remains available for tests,
but it is not the production composition described here.

This guide targets `dev` only. Following it does not modify `main`, create a
release branch or tag, publish a binary, or create a GitHub Release.

## Operator prerequisites

Before enabling permissioned mode:

1. Build `cmd/knote` and run that binary from a trusted host account.
2. Publish a current immutable artifact bundle for the workspace. Its
   `artifacts/current.json`, manifest, published projection, graph bindings,
   Claim bindings, content digests, and authorization watermark must validate as
   one selected serving revision.
3. Configure `.knote/config.yaml` with `kag.fake: false`, a reachable KAG host,
   the adapter path, and the project/namespace values expected by the provider.
4. Make the operator-owned `module:factory` provider importable by the Python
   selected through `KNOTE_PYTHON`. The provider and Python environment are part
   of the trusted deployment, but provider output is never an authorization
   decision.
5. Provision the exact OpenFGA store and authorization model referenced below.
   Policy tuples must use the same group mapping as the identity store. Knote
   owns the direct `user:<principal> member group:<group>` tuples and publishes
   them from the canonical identity membership projection.
6. Provision the tenant, trusted SSO provider, SCIM users, groups, and
   memberships in a private identity store through the trusted identity control
   plane. Do not edit the store JSON directly. The store and its parent
   directory must be accessible only to the knote service account. Each OpenFGA
   store is durably bound to one tenant; sharing it with another tenant fails
   closed.

The KAG part of `.knote/config.yaml` has this shape:

```yaml
kag:
  adapter_path: /absolute/path/to/adapters/kag/knote_kag_adapter.py
  host: https://kag.example.internal
  fake: false
  config_path: /absolute/path/to/kag_config.yaml
  project_id: "1"
  namespace: KnoteKB
  language: en
  runtime_dir: .knote/kag-runtime
```

Use absolute paths for deployment-specific files. Do not put OpenFGA tokens,
model-provider keys, or other credentials in repository configuration.

## Trusted identity control entrypoint

The production identity control plane is a non-interactive mode of the same
`knote` binary. It branches before workspace configuration or TUI
initialization and accepts no identity payload from arguments or environment
variables. `KNOTE_IDENTITY_STORE_PATH` selects the private state directory; the
complete request is read once from an inherited descriptor.

The request is one JSON object of at most 256 KiB with exactly this envelope:

```json
{
  "version": "v1",
  "operation": "tenant.register",
  "scope": {
    "version": "v1",
    "tenant_id": "tenant-acme",
    "region": "cn-east"
  },
  "input": {}
}
```

All envelope, scope, and input objects are strict. Unknown or duplicate fields,
unknown operations, a missing required field, malformed JSON, a second JSON
value, and trailing non-whitespace data are rejected before the identity store
is opened. The supported operations and their exact `input` fields are:

| Operation | Required `input` fields |
|---|---|
| `tenant.register` | No fields; use `{}`. |
| `provider.register` | `provider_id`, `issuer`, `audiences`. |
| `user.upsert` | `provider_id`, `external_id`, `external_subject_id`, `principal_id`. The user is active; grant-bearing identifiers are immutable after first registration. |
| `user.deprovision` | `provider_id`, `external_id`. |
| `group.upsert` | `provider_id`, `external_id`, `group_id`, `display_name`. The group is active; `group_id` is immutable after first registration. |
| `group.deprovision` | `provider_id`, `external_id`. |
| `membership.upsert` | `provider_id`, `group_external_id`, `user_external_id`, and required Boolean `active`. |
| `membership.replace` | `provider_id`, `group_external_id`, and required `user_external_ids` array. An empty array clears the group. |

Compute the confirmation over the exact request bytes. Only the canonical
lowercase `sha256:<64 hex characters>` digest and descriptor number appear on
the command line:

```sh
chmod 0600 /run/knote/identity/request.json
digest="$(shasum -a 256 /run/knote/identity/request.json | awk '{print $1}')"
exec 3< /run/knote/identity/request.json

KNOTE_IDENTITY_STORE_PATH='/var/lib/knote/identity' \
  /usr/local/bin/knote identity-control \
  --request-fd=3 \
  --confirm="sha256:${digest}"

exec 3<&-
```

The descriptor is consumed and closed. A digest mismatch is rejected before
any store side effect. Success emits exactly one compact, content-free JSON
receipt followed by a newline:

```json
{"version":"v1","request_digest":"sha256:<digest>","changed":true,"revision_number":2,"identity_watermark":"identity_<opaque-watermark>"}
```

No tenant, provider, subject, principal, group, membership, assertion,
credential, or secret body is returned. Failure writes only
`identity control request rejected` to standard error and exits non-zero.

## Exact runtime configuration

Real permissioned mode is enabled only by `KNOTE_PERMISSIONED=1`. For a real KAG
configuration, an unset value or `0` leaves real permissioned composition
disabled; any other value is rejected. `KNOTE_KAG_FAKE=1` separately selects the
deterministic fixture composition. When real permissioned mode is enabled, all
required values below must be present, non-empty, and free of leading or trailing
whitespace.

| Variable | Requirement |
|---|---|
| `KNOTE_PERMISSIONED` | Required literal `1`. |
| `KNOTE_IDENTITY_STORE_PATH` | Required path to the private tenant-scoped identity store provisioned by the trusted SCIM control plane. An absolute path is recommended. |
| `KNOTE_IDENTITY_ED25519_PUBLIC_KEY` | Required canonical unpadded base64url Ed25519 public key used to verify the one-shot provider-neutral assertion. |
| `KNOTE_IDENTITY_ASSERTION_FD` | Required inherited file descriptor number, at least `3`, containing one signed assertion of at most 64 KiB. The descriptor is consumed and closed before the TUI starts. Each process launch requires a fresh, unexpired assertion with a new nonce. |
| `KNOTE_KAG_PERMISSIONED_PROVIDER` | Required Python provider in `module:factory` form. |
| `KNOTE_OPENFGA_ENDPOINT` | Required absolute HTTP(S) URL. Plain HTTP is accepted only for loopback; credentials, query strings, and fragments are rejected. |
| `KNOTE_OPENFGA_STORE_ID` | Required canonical OpenFGA store ULID. |
| `KNOTE_OPENFGA_MODEL_ID` | Required canonical OpenFGA authorization-model ULID. |
| `KNOTE_OPENFGA_API_TOKEN` | Required non-empty API token, read only from the process environment. |
| `KNOTE_OPENFGA_TIMEOUT` | Optional positive Go duration; default `3s`. |
| `KNOTE_TURN_TIMEOUT` | Optional positive Go duration bounding each message or confirmation turn; default `3m`. Cancellation and terminal persistence use at most the configured duration, capped at two seconds. |
| `KNOTE_OPENFGA_CONSISTENCY` | Optional `higher_consistency` (default) or `minimize_latency`. |
| `KNOTE_PERMISSIONED_TELEMETRY_PATH` | Optional path for the content-free JSONL telemetry sink described below. |

### Phase 3 governance, audit, and residency configuration

The permissioned application constructs the residency boundary before KAG,
telemetry, audit, or governance. Invalid or contradictory settings fail startup
closed. Region lists are canonical comma-separated values with no empty or
duplicate member; their in-memory order is sorted.

| Variable | Requirement and default |
|---|---|
| `KNOTE_GOVERNANCE_REGION` | Optional canonical home region; default `local`. It becomes the trusted tenant-scope region for the process. |
| `KNOTE_GOVERNANCE_CONNECTOR_WATERMARK` | Optional content-free connector status watermark; default `connector-unconfigured-v1`. It is a governance status input, not authority to advance a connector checkpoint. |
| `KNOTE_GOVERNANCE_RESIDENCY_WATERMARK` | Optional residency-policy watermark; default `residency-local-v1`. A changed watermark invalidates stale residency checks. |
| `KNOTE_RESIDENCY_STORAGE_REGIONS` | Optional comma-separated storage allowlist; default is the home region. It covers telemetry, audit, and backup destinations. |
| `KNOTE_RESIDENCY_PROCESSING_REGIONS` | Optional comma-separated processing allowlist; default is the home region. It covers KAG processing. |
| `KNOTE_RESIDENCY_EGRESS_REGIONS` | Optional comma-separated connector-egress allowlist; default is the home region. Literal `none` creates a valid deny-all egress policy: startup succeeds, but every connector-egress callback is denied before bytes leave. |
| `KNOTE_RESIDENCY_KAG_REGION` | Optional KAG destination; default is the home region and it must be in the processing allowlist. |
| `KNOTE_RESIDENCY_TELEMETRY_REGION` | Optional telemetry destination; default is the home region and it must be in the storage allowlist. |
| `KNOTE_RESIDENCY_AUDIT_REGION` | Optional audit destination; default is the home region and it must be in the storage allowlist. |
| `KNOTE_RESIDENCY_CONNECTOR_EGRESS_REGION` | Optional connector egress destination; default is the home region. A nonempty egress allowlist must contain it; a deny-all egress policy denies its use at operation time. |
| `KNOTE_RESIDENCY_BACKUP_REGION` | Optional backup destination; default is the home region and it must be in the storage allowlist. |
| `KNOTE_PERMISSIONED_AUDIT_PATH` | Optional absolute audit root. If unset, knote uses `os.UserConfigDir()/knote/audit/<workspace-digest>`, outside the workspace and stable for the canonical workspace path. Prefer the default or an operator-owned restricted path outside Git. |

If an in-workspace override is unavoidable, use only the absolute
`<workspace>/.knote/audit` path or one of its descendants. That fixed runtime
path is excluded from dirty-state accounting and `/commit`; other in-workspace
locations, including `sources`, `artifacts`, and `evals`, are committable and
must not contain audit data. Any in-workspace audit storage remains a poor
deployment choice: prefer a private, backed-up, tenant-appropriate filesystem
outside the source repository.

`KNOTE_KAG_FAKE=1` and `KNOTE_PERMISSIONED=1` are mutually exclusive. A
workspace with `kag.fake: true` is also not a real permissioned deployment. A
working Python interpreter, selected by `KNOTE_PYTHON` or the runtime default,
and normal Eino model configuration are still required by their respective
runtime boundaries.

Example invocation:

```sh
CGO_ENABLED=0 go build -o /tmp/knote-permissioned ./cmd/knote

# The assertion is supplied by the trusted SSO gateway or secret manager. It is
# never placed in an environment variable or command-line argument.
exec 3< /run/knote/identity/assertion.jwt

KNOTE_PERMISSIONED=1 \
KNOTE_IDENTITY_STORE_PATH='/var/lib/knote/identity' \
KNOTE_IDENTITY_ED25519_PUBLIC_KEY='<canonical-base64url-ed25519-public-key>' \
KNOTE_IDENTITY_ASSERTION_FD=3 \
KNOTE_KAG_PERMISSIONED_PROVIDER='operator_provider:create' \
KNOTE_OPENFGA_ENDPOINT='https://openfga.example.internal' \
KNOTE_OPENFGA_STORE_ID='<store-ulid>' \
KNOTE_OPENFGA_MODEL_ID='<model-ulid>' \
KNOTE_OPENFGA_API_TOKEN='<token-from-secret-manager>' \
KNOTE_OPENFGA_CONSISTENCY='higher_consistency' \
KNOTE_PYTHON='/absolute/path/to/python3' \
KNOTE_EINO_PROVIDER='openai-compatible' \
KNOTE_EINO_MODEL='<model>' \
KNOTE_EINO_API_KEY='<model-key-from-secret-manager>' \
KNOTE_EINO_BASE_URL='https://model.example.internal/v1' \
/tmp/knote-permissioned --workspace /absolute/path/to/workspace

exec 3<&-
```

Prefer process injection from a secret manager over shell history for API keys,
tokens, and assertion material. `KNOTE_PERMISSIONED_PRINCIPAL` and
`KNOTE_PERMISSIONED_IDENTITY_WATERMARK` are legacy inputs and are ignored by
real permissioned mode; the verified identity snapshot is authoritative.

## Fail-closed startup boundary

The TUI is created only after the runtime has completed the following boundary:

1. validate the runtime mode and load the workspace configuration;
2. reject fake/real conflicts and incomplete or malformed permissioned
   environment configuration;
3. read the one-shot assertion descriptor, verify its Ed25519 signature, issuer,
   audience, tenant, subject, validity window, and replay nonce, then close it;
4. resolve an active SCIM identity and current group membership from the private
   tenant store without persisting the raw assertion;
5. read and validate the selected artifact metadata and published projection;
6. bind tenant, knowledge base, projection, ACL watermark, OpenFGA store/model,
   and the verified identity watermark into the initial authorization revision;
7. construct the OpenFGA client and require its environment-only token;
8. reconcile the tenant's exact canonical membership projection to OpenFGA and
   durably record a receipt for the tenant, store, model, and identity watermark;
9. construct the verified-bundle evidence loader, authorized query service,
   permissioned capability profile, and trusted authorization-context provider;
10. validate a startup authorization context whose identity watermark exactly
   matches that publication receipt before exposing query or explain
   tools or loading a resumable permissioned session.

A failure in any of these steps exits before the TUI starts. There is no partial
permissioned tool set and no fallback to legacy `kag.query`, `kag.explain`, raw
workspace summaries, or an unbound session.

Startup validates configuration and the local selected revision. A pending or
changed identity membership projection must be published successfully to
OpenFGA before startup continues; an already-current empty or unchanged receipt
does not issue a health-check write. KAG provider execution still occurs on a
protected request. A timeout, unavailable endpoint, publication failure,
provider import failure, malformed provider response, stale revision, digest
mismatch, or incomplete authorization response fails closed with a generic
public error. It does not fall back to non-permissioned content.

## Trust and threat boundaries

Trusted deployment inputs are the operator-controlled process environment, host
account, workspace security domain, current selected artifact bundle, knote Go
authorization orchestration, and the configured OpenFGA policy service. One
workspace is one plaintext security domain; do not mix source or artifact bodies
from different domains in one repository.

The authorization context is created by the runtime. Questions, model tool JSON,
provider responses, KAG search/ranking output, stale caches, citations, and
session events cannot supply or widen tenant, principal, session, model, or
watermark scope. The Python provider is trusted to process the query and the
already-authorized evidence passed to generation, but it is not trusted to name
new resources or construct citations. Retrieve output is limited to allowlisted
opaque graph object IDs; graph expansion follows verified local Claim bindings;
the final evidence set is authorized and digest-checked again before generation.

An external model may receive evidence that the current principal is authorized
to use. Revocation protects future knote reads and replay, but cannot retract
content already displayed, copied, or sent to that model.

Protected observable surfaces include:

- discovery and relevance-provider inputs;
- every graph frontier and participating Claim/entity/object path;
- evidence loading, generation inputs, answers, citations, and explain output;
- cache hits, derived-artifact reads, and session resume/replay;
- count, exists, autocomplete, pagination, details, diff, and version surfaces;
- errors, status, trace/debug data, metrics, audit data, adapter output, and
  persisted events.

Permissioned sessions expose only authorization-aware query/explain and the
explicitly allowed session or confirmed side-effect commands. A surface without
an authorization-aware projection remains hidden or unavailable.

## Content-free telemetry sink

Phase 3 retains `KNOTE_PERMISSIONED_TELEMETRY_PATH` as the opt-in sink for one
JSON object per line. Leaving it unset disables the sink. Use a restricted
absolute path managed by the operator; telemetry is operational evidence, not a
session log or audit record of protected content. The runtime validates that a
configured path is absolute, then performs each append through a serialized,
bounded best-effort write and closes the descriptor instead of retaining it.
Blocked I/O times out without delaying a protected operation indefinitely.

The schema is closed. It permits only these non-sensitive field classes:

- telemetry contract version and fixed metric-scope/event-kind/stage/outcome
  enums;
- integer aggregate counts such as candidates, allows, drops, batches, paths,
  evidence items, reconciliation additions/removals, and samples;
- elapsed durations and aggregate rate/percentile values;
- fixed budget names and pass/fail classifications.

It has no free-form diagnostic field. It must never contain questions, prompts,
answers, evidence, titles, paths, filenames, graph labels or structure, provider
output, errors, resource/graph/principal/tenant/knowledge-base/session/request
IDs, model or projection IDs, endpoints, tokens, or other secrets.

The sink is best effort and non-authoritative. Open, encode, append, flush, or
close failures never allow or deny a resource, change an authorization or
revocation result, alter returned evidence, or fail an otherwise valid request.
Telemetry records and sink errors never become TUI events, model messages, or
`.knote/sessions/*.jsonl` history. Issue #97 acceptance covers both the
allowlisted schema and a failing sink.

`metric_scope=operational` identifies per-query or reconciliation observations.
For that scope, Recall@4, Precision@4, positive/negative empty-result rates,
unauthorized path/generator participation, and P95/P99 fields are neutral zero
placeholders and must not be treated as measured values. Those cohort metrics
are produced by the deterministic acceptance suite, not by joining runtime
telemetry to protected session or evidence data.

## Governance, audit, and residency operator evidence

Generate release evidence only from the exact `dev` candidate. Start with the
authoritative deterministic entrypoint:

```sh
scripts/verify_phase3_acceptance.sh
```

It must finish with `Phase 3 deterministic acceptance passed.` The command is
the local release-evidence gate; running only one package below is useful for
diagnosis but is not a substitute.

### Governance evidence

In a disposable synthetic permissioned workspace, launch the exact candidate
binary with the identity, OpenFGA, KAG, model, governance, audit, and residency
settings documented above. An identity with direct knowledge-base editor access
may enter:

```text
/governance
```

Record only the fixed section names, aggregate counts, watermarks, states, and
audit/residency references. Do not capture the terminal if any unrelated user
content is visible. The evidence must establish:

- authorization uses higher consistency and denial occurs before the source is
  read;
- an unauthorized section is omitted, not rendered with a revealing zero;
- connector and simulation lists are canonical and deterministic;
- rendered output contains no protected body, credential, path, prompt, or
  provider diagnostic;
- a successful view appends a content-free `governance.view` audit reference.
  Because the snapshot is loaded before its own audit append, a second view may
  be needed to observe the first view's reference.

The reproducible non-interactive evidence is:

```sh
go test -count=1 ./internal/governance ./internal/runtime ./cmd/knote \
  -run 'Governance|governance'
```

### Audit evidence

Opening the permissioned application verifies every existing tenant ledger and
durable head. Append occurs only after residency authorization. A tampered,
truncated, reordered, cross-tenant, copied, duplicate-ID, or protected-field
ledger fails closed; crash recovery applies only to an exact marked
transaction.

```sh
go test -count=1 ./internal/audit ./cmd/knote -run 'Audit|audit'
go test -race -count=1 ./internal/audit
```

Do not tamper with a deployment ledger to prove this behavior. Use the
temporary stores created by the tests. Release evidence records only test
status and the candidate SHA, never ledger bytes or tenant partitions.

### Residency evidence

Residency must be checked before persistence, network access, subprocess start,
or callback invocation. The deny-all connector policy is a required operator
case:

```sh
KNOTE_RESIDENCY_EGRESS_REGIONS=none \
  go test -count=1 ./cmd/knote \
  -run 'TestPermissionedResidencyBoundaryAllowsDenyAllEgressPolicy|TestPermissionedResidencyBoundaryChecksBeforeConnectorOrBackupBytes'

go test -count=1 ./internal/residency ./internal/knowledge/kag ./cmd/knote \
  -run 'Residency|residency'
```

Required evidence is callback count `0` and persisted/egressed byte count `0`
for denied operations. Governance may expose only fixed content-free violation
references; it must not expose the denied payload or destination credentials.

## Troubleshooting without disclosure

- **Startup rejects configuration:** check only whether each required variable
  is present and whether IDs/URLs match the documented shape. Do not print the
  environment or token values.
- **Selected bundle is rejected:** rebuild and republish from the trusted source
  pipeline. Inspect manifest validation classes and counts, not source bodies or
  full artifact files.
- **OpenFGA requests fail closed:** verify DNS/TLS/loopback reachability, the
  store/model pairing, token provisioning, timeout, and consistency mode outside
  the TUI. Do not enable shell tracing or dump HTTP authorization headers.
- **Provider requests fail closed:** verify the selected Python can import the
  configured module and that the provider implements the strict retrieve and
  generate contract. Provider stdout/stderr is deliberately suppressed; do not
  patch it into user-visible or session output.
- **Resume or citation becomes unavailable:** treat revision, identity, ACL,
  projection, session, and revocation mismatches as expected fail-closed causes.
  Start a new authorized session instead of editing persisted envelopes.
- **Telemetry file is absent or stops growing:** verify the parent directory,
  ownership, permissions, and free space independently. A sink failure is not
  evidence that authorization failed and must not be surfaced by adding content
  or secrets to logs.

Never troubleshoot permissioned mode with `set -x`, an environment dump, raw
OpenFGA requests/responses, provider stdout/stderr, source/artifact bodies, model
prompts, or session files. Use fixed error classes, aggregate counts, and the
deterministic issue #97 acceptance paths in
`docs/permissioned-kag-acceptance.md`.
