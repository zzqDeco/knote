# Permissioned KAG Operations

This guide applies to the opt-in real permissioned composition on `dev`. It
documents the operator and security contract exercised by issue #78; it is not
a GitHub Release announcement. Deterministic fixture mode remains available for
tests, but it is not the production composition described here.

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
   The principal and tuples in that store must use the same identity mapping as
   the selected workspace projection.

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
| `KNOTE_PERMISSIONED_PRINCIPAL` | Required raw principal ID mapped to the OpenFGA `user` subject. Do not include the `user:` prefix; knote adds it to checks. The value comes from the trusted process environment, never tool input. |
| `KNOTE_PERMISSIONED_IDENTITY_WATERMARK` | Required current identity revision selected by the operator. |
| `KNOTE_KAG_PERMISSIONED_PROVIDER` | Required Python provider in `module:factory` form. |
| `KNOTE_OPENFGA_ENDPOINT` | Required absolute HTTP(S) URL. Plain HTTP is accepted only for loopback; credentials, query strings, and fragments are rejected. |
| `KNOTE_OPENFGA_STORE_ID` | Required canonical OpenFGA store ULID. |
| `KNOTE_OPENFGA_MODEL_ID` | Required canonical OpenFGA authorization-model ULID. |
| `KNOTE_OPENFGA_API_TOKEN` | Required non-empty API token, read only from the process environment. |
| `KNOTE_OPENFGA_TIMEOUT` | Optional positive Go duration; default `3s`. |
| `KNOTE_OPENFGA_CONSISTENCY` | Optional `higher_consistency` (default) or `minimize_latency`. |
| `KNOTE_PERMISSIONED_TELEMETRY_PATH` | Optional path for the content-free JSONL telemetry sink described below. |

`KNOTE_KAG_FAKE=1` and `KNOTE_PERMISSIONED=1` are mutually exclusive. A
workspace with `kag.fake: true` is also not a real permissioned deployment. A
working Python interpreter, selected by `KNOTE_PYTHON` or the runtime default,
and normal Eino model configuration are still required by their respective
runtime boundaries.

Example invocation:

```sh
CGO_ENABLED=0 go build -o /tmp/knote-permissioned ./cmd/knote

KNOTE_PERMISSIONED=1 \
KNOTE_PERMISSIONED_PRINCIPAL='<openfga-user-id>' \
KNOTE_PERMISSIONED_IDENTITY_WATERMARK='<identity-revision>' \
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
```

Prefer process injection from a secret manager over shell history for the two
credentials shown as placeholders.

## Fail-closed startup boundary

The TUI is created only after the runtime has completed the following boundary:

1. validate the runtime mode and load the workspace configuration;
2. reject fake/real conflicts and incomplete or malformed permissioned
   environment configuration;
3. read and validate the selected artifact metadata and published projection;
4. bind tenant, knowledge base, projection, ACL watermark, OpenFGA store/model,
   and identity watermark into the initial authorization revision;
5. construct the OpenFGA client and require its environment-only token;
6. construct the verified-bundle evidence loader, authorized query service,
   permissioned capability profile, and trusted authorization-context provider;
7. validate a startup authorization context before exposing query or explain
   tools or loading a resumable permissioned session.

A failure in any of these steps exits before the TUI starts. There is no partial
permissioned tool set and no fallback to legacy `kag.query`, `kag.explain`, raw
workspace summaries, or an unbound session.

Startup validates configuration and the local selected revision; it does not
prove that a remote OpenFGA endpoint is reachable or import and execute the KAG
provider. Those operations occur on a protected request. A timeout, unavailable
endpoint, provider import failure, malformed provider response, stale revision,
digest mismatch, or incomplete authorization response fails that request closed
with a generic public error. It does not fall back to non-permissioned content.

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

Issue #78 defines `KNOTE_PERMISSIONED_TELEMETRY_PATH` as the opt-in sink for one
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
`.knote/sessions/*.jsonl` history. Issue #78 acceptance must cover both the
allowlisted schema and a failing sink.

`metric_scope=operational` identifies per-query or reconciliation observations.
For that scope, Recall@4, Precision@4, positive/negative empty-result rates,
unauthorized path/generator participation, and P95/P99 fields are neutral zero
placeholders and must not be treated as measured values. Those cohort metrics
are produced by the deterministic acceptance suite, not by joining runtime
telemetry to protected session or evidence data.

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
deterministic issue #78 acceptance paths in
`docs/permissioned-kag-acceptance.md`.
