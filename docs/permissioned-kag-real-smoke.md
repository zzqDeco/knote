# Optional Real OpenFGA and KAG Smoke

These procedures are manual compatibility checks. They are deliberately
separate from the deterministic issue #41 gate and must not be added to CI.
They do not prove an end-to-end real permissioned query: the current runtime
wires permissioned retrieval only in fake KAG mode, and the real adapter rejects
the three permissioned primitives with `unsupported_primitive`.

## Credential rules

- Use local or disposable stores and workspaces.
- Keep API tokens and model-provider credentials only in the invoking shell or
  an ignored local configuration. Never add them to Git, command output, test
  fixtures, GitHub Actions secrets for this smoke, or generated artifacts.
- Do not enable `KNOTE_KAG_FAKE` for the KAG procedure.
- Sanitized evidence may include versions, opaque IDs, counts, durations, and
  allow/deny outcomes. Do not retain protected bodies, prompts, traces, paths,
  or relation labels.

## OpenFGA model test

This repository-pinned command is credential-free and already runs in CI:

```sh
GOTOOLCHAIN=go1.25.12 go run github.com/openfga/cli/cmd/fga@v0.7.17 model test --tests internal/authz/model/authorization.fga.yaml
```

It validates `internal/authz/model/authorization.fga` against the direct-share,
cross-tenant, group-membership, restricted-child, and revoke truth tables in
`internal/authz/model/authorization.fga.yaml`.

## Live local OpenFGA

Prerequisites:

- Docker with ports 8080 and 3000 available.
- Go toolchain download access for the pinned OpenFGA CLI.
- No API token; this procedure binds only to loopback and uses an ephemeral
  in-memory OpenFGA server.

Start OpenFGA in one terminal:

```sh
docker run --rm --name knote-openfga -p 127.0.0.1:8080:8080 -p 127.0.0.1:3000:3000 openfga/openfga run
```

Create a disposable store and write the checked-in model:

```sh
GOTOOLCHAIN=go1.25.12 go run github.com/openfga/cli/cmd/fga@v0.7.17 store create --api-url http://127.0.0.1:8080 --name knote-permissioned-kag-smoke --model internal/authz/model/authorization.fga --format fga
```

Record `.store.id` from the JSON response as `<store-id>`, then write a minimal
same-organization direct-share fixture:

```sh
GOTOOLCHAIN=go1.25.12 go run github.com/openfga/cli/cmd/fga@v0.7.17 tuple write --api-url http://127.0.0.1:8080 --store-id <store-id> user:alice member organization:acme
GOTOOLCHAIN=go1.25.12 go run github.com/openfga/cli/cmd/fga@v0.7.17 tuple write --api-url http://127.0.0.1:8080 --store-id <store-id> organization:acme organization document:smoke
GOTOOLCHAIN=go1.25.12 go run github.com/openfga/cli/cmd/fga@v0.7.17 tuple write --api-url http://127.0.0.1:8080 --store-id <store-id> user:alice viewer document:smoke
```

Alice must be allowed and Bob must be denied with higher consistency:

```sh
GOTOOLCHAIN=go1.25.12 go run github.com/openfga/cli/cmd/fga@v0.7.17 query check --api-url http://127.0.0.1:8080 --store-id <store-id> --consistency HIGHER_CONSISTENCY user:alice can_view document:smoke
GOTOOLCHAIN=go1.25.12 go run github.com/openfga/cli/cmd/fga@v0.7.17 query check --api-url http://127.0.0.1:8080 --store-id <store-id> --consistency HIGHER_CONSISTENCY user:bob can_view document:smoke
```

Delete Alice's direct share and repeat her check. The result must change to
deny; record the elapsed delete-to-deny time as an observational revocation
sample, not as CI evidence:

```sh
GOTOOLCHAIN=go1.25.12 go run github.com/openfga/cli/cmd/fga@v0.7.17 tuple delete --api-url http://127.0.0.1:8080 --store-id <store-id> user:alice viewer document:smoke
GOTOOLCHAIN=go1.25.12 go run github.com/openfga/cli/cmd/fga@v0.7.17 query check --api-url http://127.0.0.1:8080 --store-id <store-id> --consistency HIGHER_CONSISTENCY user:alice can_view document:smoke
```

Stop the container with `Ctrl-C`. `internal/authz/openfga_test.go` separately
proves the Go SDK request, model pinning, response validation, timeout, and
fail-closed behavior against local HTTP test servers. There is currently no
supported `knote` CLI flag that wires this disposable store into the runtime;
do not invent one. `internal/authz.NewOpenFGA` also requires
`KNOTE_OPENFGA_API_TOKEN`, so this unauthenticated service check does not claim
to exercise that constructor.

## Real OpenSPG/KAG

Prerequisites:

- A Python interpreter that can import the repository's supported
  `openspg-kag` 0.8.0 environment.
- A reachable OpenSPG/KAG service, defaulting to
  `http://127.0.0.1:8887`.
- Any model-provider configuration required by the local KAG configuration,
  supplied only through the local environment.
- Git, because the smoke creates an ephemeral repository when no workspace is
  supplied.

Run the existing smoke script from the repository root:

```sh
KNOTE_PYTHON=/path/to/python KNOTE_KAG_HOST=http://127.0.0.1:8887 scripts/smoke_real_kag.sh
```

To inspect a prepared local workspace instead of the ephemeral fixture:

```sh
KNOTE_PYTHON=/path/to/python KNOTE_KAG_HOST=http://127.0.0.1:8887 KNOTE_REAL_KAG_WORKSPACE=/absolute/path/to/workspace scripts/smoke_real_kag.sh
```

`scripts/smoke_real_kag.sh` invokes `tests/smoke/kag_real_smoke.py`. Success
means:

1. `kag.health`, `kag.build`, legacy `kag.query`, and legacy `kag.explain`
   complete against the local service.
2. `kag.retrieve`, `kag.expand`, and `kag.generate` each return the typed
   `unsupported_primitive` error.

The second condition is a security assertion: real permissioned primitives
must remain closed until a pre-generation, per-hop implementation is proven.
Legacy query/explain output is compatibility evidence only and must not be used
to satisfy issue #41 recall, precision, path-completeness, or no-leak gates.

## Smoke record

Keep a short local record with the Git commit, OpenFGA/OpenSPG/KAG versions,
sanitized endpoint host, model ID, projection version, pass/fail per step, and
observed durations. A failure does not weaken the deterministic CI gate; it
blocks any claim that the corresponding real integration is operational.
