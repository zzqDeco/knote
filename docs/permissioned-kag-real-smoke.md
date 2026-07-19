# Phase 3 Permissioned OpenFGA and KAG Smoke

This document defines the disposable live-service evidence for Phase 3 issue
#97 on `dev`. Live smoke checks pinned external-service compatibility after the
deterministic release gate passes. It does not modify `main`, create a tag,
publish an artifact, or create a GitHub Release.

There are two separate live boundaries:

1. `scripts/smoke_phase3_openfga.sh` is the required Phase 3 OpenFGA gate. It
   proves the real authorization model, scoped Check/BatchCheck behavior, and
   revocation against a disposable OpenFGA service.
2. `scripts/smoke_permissioned_graph_real.sh` is the inherited OpenSPG/KAG
   compatibility gate. It proves the graph-provider path with public-synthetic
   data, but it is not a substitute for Phase 3 identity, connector, tool,
   governance, audit, or residency acceptance.

Neither live command replaces `scripts/verify_phase3_acceptance.sh`, which is
the authoritative deterministic local release-evidence entrypoint.

## Credential and data rules

- Use only the checked-in public-synthetic fixtures and temporary identifiers.
- Do not use production endpoints, stores, projects, workspaces, content,
  identities, assertions, model-provider credentials, or API tokens.
- Do not set `KNOTE_KAG_FAKE` for either live command.
- Bind every service to loopback or an explicitly disposable private stack.
- Do not enable shell tracing, dump the environment, print raw OpenFGA
  requests/responses, or retain provider/service logs without first proving
  they contain only synthetic fixture data and no headers or tokens.
- A cleanup failure fails the smoke. Do not preserve a stack that may contain
  anything other than the public-synthetic fixture.

## Required deterministic prerequisite

From the repository root at the exact candidate SHA:

```sh
scripts/verify_phase3_acceptance.sh
```

The script takes no arguments and must finish with:

```text
Phase 3 deterministic acceptance passed.
```

It includes the baseline Go/Python tests, real-adapter self-test, exact built
binary smoke, OpenFGA model test, race tests, vet, and Linux/Windows builds.

## Required Phase 3 OpenFGA smoke

### Pinned dependencies

| Component | Version or image digest |
|---|---|
| OpenFGA CLI | `github.com/openfga/cli/cmd/fga@v0.7.17` |
| OpenFGA server | `openfga/openfga:v1.15.1@sha256:8543200bf85878c968d73da46c4f0e31ba1f63ed3675b71122f1133b0e9d97eb` |
| Go toolchain for CLI installation | `go1.25.12` |

Prerequisites are Docker Desktop or Docker Engine, Go, and Python 3. The script
checks each command, requires a responsive Docker daemon, and verifies the
installed CLI module version before starting the service.

Run:

```sh
scripts/smoke_phase3_openfga.sh
```

The script takes no arguments. It:

1. creates a private temporary directory and random API token;
2. starts the pinned OpenFGA image with an in-memory datastore, pre-shared-key
   authentication, the playground disabled, and a random loopback port;
3. creates a temporary store and uploads
   `internal/authz/model/authorization.fga`;
4. runs `TestPhase3OpenFGALiveSmoke` from
   `internal/authz/phase3_openfga_live_test.go` with higher consistency and the
   exact returned model ID;
5. removes the container, token file, temporary CLI, and temporary directory;
6. prints `phase3 OpenFGA smoke passed` only if test and cleanup both succeed.

The live test proves:

- a complete user delegation, agent assignment, and task assignee scope permits
  `can_view` when the underlying user grant also exists;
- a BatchCheck item missing the task assignee evidence denies while a complete
  item in the same request allows;
- correlation order and ordinary deny survive the real BatchCheck boundary;
- deleting the user's viewer tuple invalidates the otherwise complete
  user-agent-task scope on the next higher-consistency Check.

This smoke does not prove connector replay/reconciliation, KAG retrieval,
runtime/TUI tool publication, policy simulation, audit tamper detection, or
residency. Those remain mandatory deterministic #97 matrix rows.

## Inherited OpenSPG/KAG live compatibility

The existing graph smoke remains useful after the required OpenFGA gate. It
uses the checked-in `public-synthetic` fixture and a disposable OpenFGA plus
OpenSPG/KAG stack.

### Additional pinned dependencies

| Component | Version or image digest |
|---|---|
| OpenSPG/KAG Python | `0.8.0` |
| knext Python | `0.8.0` |
| OpenSPG server | `sha256:fe6708deef9ebb8da8da7b1cb643e83b827769a5be8811961311639aa1f2cb88` |
| OpenSPG MySQL | `sha256:71eb546d5fc5faf70b3d8a358c022f601591b54a029b79298f2fa0302e46de9a` |
| OpenSPG Neo4j | `sha256:4bc5b7f6b83d333b1d2c8f60ac145c068d77d50bca65b3a07c927f9e2a541eb9` |
| OpenSPG MinIO | `sha256:9493c8e8f77edb10d556255d49ba8b5761b0fe57889235dfd10619c0513da007` |
| Python | `>= 3.11` with `openspg-kag==0.8.0` and `knext==0.8.0` |

Run:

```sh
KNOTE_PERMISSIONED_GRAPH_REAL_SMOKE=1 \
KNOTE_PYTHON=/absolute/path/to/openspg-kag-0.8-python \
  scripts/smoke_permissioned_graph_real.sh
```

The inherited smoke validates unknown-principal denial, KAG project/schema
setup, typed vertex and edge upsert, bounded live graph probes, exact authorized
object retrieval, entity-to-Claim and Claim-to-object expansion, digest-checked
evidence load, allowlisted generation, and higher-consistency replay denial
after revocation.

Its credential-free deterministic half is already run by
`scripts/verify_phase3_acceptance.sh`:

```sh
/usr/bin/python3 tests/smoke/permissioned_graph_real_smoke.py --self-test
```

The deterministic half proves fixture and adapter behavior. It does not claim a
live OpenSPG pass or execute the built `cmd/knote` boundary.

## Existing disposable OpenSPG stack

An externally managed endpoint is accepted only when the entire stack is
explicitly declared disposable. The temporary project remains in that stack
because OpenSPG 0.8 protects deletion with its login session; the caller must
destroy the stack and volumes after the run.

```sh
KNOTE_PERMISSIONED_GRAPH_REAL_SMOKE=1 \
KNOTE_PYTHON=/absolute/path/to/openspg-kag-0.8-python \
KNOTE_KAG_HOST=http://127.0.0.1:8887 \
KNOTE_OPENSPG_DISPOSABLE=1 \
KNOTE_OPENSPG_SERVER_VERSION='v0.8.0@sha256:fe6708deef9ebb8da8da7b1cb643e83b827769a5be8811961311639aa1f2cb88' \
  scripts/smoke_permissioned_graph_real.sh
```

For an external OpenFGA endpoint used by the inherited graph smoke, also set
`KNOTE_OPENFGA_API_URL` and exact `KNOTE_OPENFGA_SERVER_VERSION`. Keep
`KNOTE_OPENFGA_API_TOKEN` only in the invoking environment.

`KNOTE_OPENFGA_API_URL` is an inherited smoke-orchestration variable. The real
`cmd/knote` operator boundary and the Phase 3 OpenFGA client use
`KNOTE_OPENFGA_ENDPOINT`; do not silently substitute one for the other.

## Release evidence

Record the exact candidate SHA, target branch `dev`, command, UTC completion
time, pinned versions, cleanup result, final fixed pass line, and current-head CI
and review URLs in the PR and issue completion comments, following
`docs/phase3-release-evidence.md`. Do not copy temporary store, model, tenant,
principal, agent, task, resource, endpoint, or token values into the record.

The OpenFGA smoke is pass/fail compatibility evidence. Its wall-clock duration
is diagnostic only; deterministic BatchCheck and revocation budgets are proved
by the release gate described in `docs/permissioned-kag-acceptance.md`.

## Troubleshooting without disclosure

- Resolve preflight failures from the fixed missing-command, version, Docker,
  port, store, model, service-readiness, test, or cleanup stage.
- Verify Docker health and exit status before reading raw logs. Do not retain or
  share logs until they are confirmed synthetic and token free.
- Verify only version and importability for KAG provider failures. Provider
  stdout/stderr is intentionally suppressed and must not be routed into release
  evidence.
- A live-smoke failure does not justify widening an allowlist, lowering
  consistency, changing a deny into an empty success, disabling residency,
  skipping confirmation, or enabling a legacy fallback.
