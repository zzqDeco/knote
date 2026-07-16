# Phase 2 Permissioned Graph Smoke

This is the optional live compatibility path retained by issue #78. It uses only
the checked-in `public-synthetic` fixture and starts a disposable OpenFGA +
OpenSPG/KAG stack. It is separate from mandatory acceptance because it pulls
several service images and requires an `openspg-kag` Python environment. CI runs
the deterministic offline half and must separately run the issue #78 built Go
binary through real permissioned composition.

A live pass is external-service compatibility evidence. It does not replace the
deterministic `scripts/smoke_permissioned_binary.sh` gate and does not publish or
imply a GitHub Release.

## Credential and data rules

- Do not set `KNOTE_KAG_FAKE` for the live command.
- Do not use production endpoints, stores, projects, workspaces, content, or
  model-provider credentials.
- The default Compose stack publishes only its random loopback OpenSPG port.
  Its fixed internal service passwords are public fixture values and disappear
  with the disposable volumes.
- The script emits one sorted JSON result. It suppresses provider stdout/stderr
  and never emits content, prompts, relation labels, API tokens, or model IDs.
- Do not enable shell tracing, dump process environments, or attach raw service,
  provider, workspace, or HTTP logs to a smoke result.
- `KEEP_KNOTE_PERMISSIONED_GRAPH_REAL_WORKSPACE=1` may retain the synthetic
  workspace for debugging. Never use that option with non-synthetic input.

## Exact versions

The repository pins the following compatibility set:

| Component | Version or image digest |
|---|---|
| OpenFGA CLI | `github.com/openfga/cli/cmd/fga@v0.7.17` |
| OpenFGA server | `openfga/openfga:v1.15.1@sha256:8543200bf85878c968d73da46c4f0e31ba1f63ed3675b71122f1133b0e9d97eb` |
| OpenSPG/KAG Python | `0.8.0` |
| knext Python | `0.8.0` |
| OpenSPG server | `sha256:fe6708deef9ebb8da8da7b1cb643e83b827769a5be8811961311639aa1f2cb88` |
| OpenSPG MySQL | `sha256:71eb546d5fc5faf70b3d8a358c022f601591b54a029b79298f2fa0302e46de9a` |
| OpenSPG Neo4j | `sha256:4bc5b7f6b83d333b1d2c8f60ac145c068d77d50bca65b3a07c927f9e2a541eb9` |
| OpenSPG MinIO | `sha256:9493c8e8f77edb10d556255d49ba8b5761b0fe57889235dfd10619c0513da007` |
| Python | `>= 3.11` |

## Deterministic CI half

This command is credential-free and runs in `.github/workflows/ci.yml`:

```sh
python3 tests/smoke/permissioned_graph_real_smoke.py --self-test
```

It materializes the same deterministic projection twice and requires identical
manifest digests. It then exercises real adapter mode for discover, retrieve,
two per-hop expands, exact evidence load, generate, and replay denial with a
local allowlisted provider. It does not claim live OpenSPG coverage or execute
the built `cmd/knote` production-composition boundary.

## Optional disposable live command

Prerequisites:

- Docker Desktop or Docker Engine with Compose v2;
- Go, used to install the pinned CLI when needed and to verify a supplied
  `KNOTE_FGA_BIN` against its embedded module version;
- Python 3.11 or newer with `openspg-kag==0.8.0` and `knext==0.8.0` importable.

From the repository root:

```sh
KNOTE_PERMISSIONED_GRAPH_REAL_SMOKE=1 \
KNOTE_PYTHON=/absolute/path/to/openspg-kag-0.8-python \
scripts/smoke_permissioned_graph_real.sh
```

The command starts all pinned containers on random loopback ports, creates a
temporary OpenFGA store/model and OpenSPG project, and then validates:

1. unknown-principal denial before retrieval;
2. a real KAG/knext project create and schema sync;
3. separate typed vertex upserts plus one `owns` edge;
4. live `ReasonerClient.query_node` and bounded `syn_execute` graph probes;
5. real adapter retrieve restricted to the exact allowed graph object ID;
6. entity-to-Claim and Claim-to-object expansion using the checked-in binding;
7. exact digest-checked evidence load and allowlisted generation;
8. higher-consistency OpenFGA revoke and replay denial before load/generate.

The exit trap removes the OpenFGA container and runs
`docker compose down -v --remove-orphans` for OpenSPG. A cleanup failure changes
an otherwise successful run to failure and is also reported after a failed run.
The pass record contains only fixed version-verification classes, stage names,
counts, and durations. It contains no protected content, resource/principal
identifiers, endpoint credentials, provider diagnostics, or service output.

The live `replay_denial` stage rechecks the stale capsule through the real
OpenFGA store and proves that content load and generation are not called after
denial. The production runtime session-replay path is exercised separately by
`internal/runtime/phase2_graph_replay_acceptance_test.go`.

## Existing disposable OpenSPG stack

An externally managed endpoint is accepted only when the caller explicitly
declares that the whole stack is disposable. The script leaves the temporary
project in that stack because OpenSPG 0.8 protects project deletion with its
login session; the caller must destroy the stack and its volumes after the run.
External endpoint versions are marked `caller-declared` in the pass record and
cannot support a repository-pinned live compatibility claim; that claim requires
the default digest-pinned stack and `repository-pinned-image-digest` markers.

```sh
KNOTE_PERMISSIONED_GRAPH_REAL_SMOKE=1 \
KNOTE_PYTHON=/absolute/path/to/openspg-kag-0.8-python \
KNOTE_KAG_HOST=http://127.0.0.1:8887 \
KNOTE_OPENSPG_DISPOSABLE=1 \
KNOTE_OPENSPG_SERVER_VERSION='v0.8.0@sha256:fe6708deef9ebb8da8da7b1cb643e83b827769a5be8811961311639aa1f2cb88' \
scripts/smoke_permissioned_graph_real.sh
```

For an external OpenFGA endpoint, also set `KNOTE_OPENFGA_API_URL` and the exact
`KNOTE_OPENFGA_SERVER_VERSION`. Keep any `KNOTE_OPENFGA_API_TOKEN` only in the
invoking environment. Do not retain shell traces or service logs containing it.

`KNOTE_OPENFGA_API_URL` is a smoke-script orchestration variable. The real
`cmd/knote` operator boundary uses `KNOTE_OPENFGA_ENDPOINT`; see
`docs/permissioned-kag-operations.md` and do not silently substitute one for the
other.

## Troubleshooting without content or secrets

- A preflight failure should be resolved from the named missing command,
  declared version, or generic stage. Do not add environment values to the
  preflight output.
- If a container is unhealthy, inspect its health and exit status first. Do not
  retain or share raw logs until they have been verified to contain only the
  checked-in synthetic fixture and no token/header values.
- If provider import or KAG probing fails, verify the selected Python and pinned
  package versions with version-only commands. Provider stdout/stderr is
  intentionally suppressed and must not be routed into the result JSON.
- If OpenFGA fails, verify loopback reachability, declared server version, and
  store/model setup without printing `KNOTE_OPENFGA_API_TOKEN` or raw check
  requests/responses.
- If cleanup fails, rerun `docker compose down -v --remove-orphans` against the
  generated project name and remove the disposable OpenFGA container. Do not
  preserve the stack as a debugging shortcut when any non-synthetic input may
  have been used.
- A live-smoke failure does not justify weakening authorization, expanding an
  allowlist, enabling a legacy fallback, or copying content into diagnostics.

## Other validation

The authorization model remains a separate credential-free gate:

```sh
GOTOOLCHAIN=go1.25.12 go run github.com/openfga/cli/cmd/fga@v0.7.17 model test \
  --tests internal/authz/model/authorization.fga.yaml
```

`scripts/smoke_real_kag.sh` remains the legacy build/query/explain compatibility
check. Its output is not permissioned retrieval, graph-path, or no-leak evidence.
