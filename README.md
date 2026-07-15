# knote

`knote` is a local knowledge-workspace agentic TUI. It opens a transcript-first terminal interface in the current directory and helps build, query, version, and evaluate a local knowledge base.

## Version Status

`v0.1.1` is the published runtime/Eino baseline. The `v0.2.0` release line adds the permissioned KAG serving foundation and real primitive-provider path: OpenFGA-backed authorization, deterministic projection and graph bindings, body-free retrieval primitives, bounded per-hop authorized Claim traversal, revocation-safe cache/citation/session replay, and deterministic plus live OpenFGA/OpenSPG acceptance gates. The CLI currently selects the authorization-aware query tools only in deterministic fake mode; real operator runtime composition is not enabled by default.

This MVP is Go-first:

- `cmd/knote`: single CLI/TUI binary
- `internal/tui`: Bubble Tea transcript, composer, overlays, pickers, and status line
- `internal/runtime`: Eino-only session/thread lifecycle, event dispatch, task controls, slash routing, confirm routing, and runner management
- `internal/knowledge/versioned`: versioned build/query/explain/eval/diff/commit/release/checkout/status facade
- `internal/eino/tools`: shallow Eino `InvokableTool` adapters over the versioned knowledge facade
- `internal/runtime/eino`: OpenAI-compatible Eino ChatModelAgent runner bridge
- `internal/repository/local`: local config, sessions, artifacts, evals, and Git versions
- `internal/knowledge/kag`: Go boundary for fake/real OpenSPG/KAG backends
- `adapters/kag`: Python NDJSON adapter for OpenSPG/KAG

## Quick Start

```bash
CGO_ENABLED=0 go build -o bin/knote ./cmd/knote
KNOTE_KAG_FAKE=1 \
KNOTE_EINO_PROVIDER=openai-compatible \
KNOTE_EINO_MODEL=<model> \
KNOTE_EINO_API_KEY=<api-key> \
KNOTE_EINO_BASE_URL=<openai-compatible-base-url> \
./bin/knote --workspace tests/fixtures/basic-kb
```

`KNOTE_KAG_FAKE=1` only selects the deterministic KAG adapter; the Eino ChatModel runtime still requires an OpenAI-compatible model configuration.

Inside the TUI:

```text
> /build
> 当前知识库的核心结论是什么？
> /versions
> /diff
> /commit
```

Side-effecting commands (`/build`, `/commit`, `/release`, `/checkout`) open an inline confirmation prompt. Press `Enter` or `y` to approve once, and `n` or `Esc` to cancel. `/eval` currently fails closed because the legacy evaluation path calls non-permissioned explain; it will remain unavailable until evaluation runs entirely through the authorized evidence boundary.

Useful startup flags:

```bash
./bin/knote --workspace <path>
./bin/knote --resume <session-id>
./bin/knote --version
./bin/knote --help
```

## KAG Modes

The Python adapter is designed for OpenSPG/KAG `0.8.0`. For local development without OpenSPG running, set `KNOTE_KAG_FAKE=1` to use the adapter's deterministic fixture mode.

```bash
KNOTE_KAG_FAKE=1 go test ./...
scripts/smoke_fake_mvp.sh
```

`scripts/smoke_fake_mvp.sh` reuses `bin/knote` when it already exists; set `KNOTE_BIN=/path/to/knote` to smoke a different binary. On macOS it drives `go run` by default to avoid local unsigned-binary PTY startup flakiness; set `KNOTE_SMOKE_FORCE_BIN=1` to force the built binary.

If your preferred Python is not the system interpreter, set `KNOTE_PYTHON=/path/to/python`.

For real KAG execution:

1. Start OpenSPG locally at `http://127.0.0.1:8887`.
2. Install `openspg-kag` in the Python environment used by `KNOTE_PYTHON`.
3. Put Markdown or text sources under `sources/`.
4. Run `scripts/smoke_real_kag.sh` against a disposable OpenSPG project or stack before a release candidate. The compatibility smoke does not remove server-side project data.

The Phase 2 permissioned graph smoke is separate from that legacy compatibility
check. It starts pinned disposable OpenFGA and OpenSPG containers, uses only the
checked-in public synthetic fixture, and removes its containers and volumes on
exit:

```bash
KNOTE_PERMISSIONED_GRAPH_REAL_SMOKE=1 \
KNOTE_PYTHON=/path/to/openspg-kag-0.8-python \
scripts/smoke_permissioned_graph_real.sh
```

CI runs the credential-free deterministic half with
`python3 tests/smoke/permissioned_graph_real_smoke.py --self-test`. See
`docs/permissioned-kag-real-smoke.md` for exact image digests and external-stack
options.

The adapter writes a sorted JSON corpus and generated starter config under `.knote/kag-runtime/`; copy that config to `.knote/kag_config.yaml` when you need custom model, namespace, or project settings. Runtime KAG cache is ignored by Git.

## Sessions

Sessions are JSONL event logs under `.knote/sessions/`. They are retained until the workspace owner removes them; `/clear` only clears the current TUI projection and does not delete history. knote creates the session directory with owner-only access (`0700`) and session data with owner-only access (`0600`) on filesystems that support POSIX permissions.

Permissioned sessions also persist a metadata-only authorization envelope. Resume replays history only when the current tenant, knowledge base, principal, authorization model, identity and ACL watermarks, task scope, and consistency preference still match that envelope; missing or changed authorization fails closed before history is loaded. `/new` creates a fresh session, while `/resume` lists recent sessions with matching authorization envelopes and `/resume <session-id>` restores an authorized one. Revocation protects future access but cannot retract content that a user already viewed or copied.

## Runtime Layers

The TUI talks to `internal/runtime`, not directly to KAG, Git, repositories, or KAG adapters. Runtime is Eino-only: slash commands are routed deterministically by runtime, and natural-language turns go through the Eino ADK ChatModelAgent with knote tools.

```bash
KNOTE_EINO_PROVIDER=openai-compatible \
KNOTE_EINO_MODEL=gpt-4o-mini \
KNOTE_EINO_API_KEY=your-api-key \
KNOTE_EINO_BASE_URL=https://api.openai.com/v1 \
./bin/knote --workspace tests/fixtures/basic-kb
```

`KNOTE_EINO_MODEL_PROFILE` selects a profile from `.knote/config.yaml` and defaults to `default`. Environment variables override the selected profile. `OPENAI_MODEL`, `OPENAI_API_KEY`, and `OPENAI_BASE_URL` are also accepted; when those overrides are present, provider defaults to `openai-compatible`. `KNOTE_EINO_REASONING_EFFORT` accepts `low`, `medium`, or `high`. `KNOTE_RUNTIME_MODE=direct` is rejected.

Mutating Eino tools require a runtime side-effect gate, matching the TUI confirmation rule for `/build`, `/commit`, `/release`, and `/checkout`.

For a local CLIProxyAPI/OpenAI-compatible smoke, keep the proxy running and use:

```bash
KNOTE_EINO_BASE_URL=http://127.0.0.1:8317/v1 \
KNOTE_EINO_MODEL=gpt-5.3-codex-spark \
KNOTE_EINO_REASONING_EFFORT=low \
scripts/smoke_eino_local_proxy.sh
```

The script probes `/v1/models`, starts the Eino-only TUI, requires the model to call the permissioned `knote_query` tool, and waits for the evidence-bound `knote-authorized-ok` response. Set `KNOTE_EINO_API_KEY` explicitly, set `KNOTE_CLIPROXY_CONFIG`, or let the script try documented CLIProxyAPI default config paths such as `~/.cli-proxy-api/config.yaml` and Homebrew `etc/cliproxyapi.conf`.

## Versions And Eval

`knote` treats Git commits as knowledge versions, Git tags as release versions, and branches as candidate experiments.

- `/diff` shows current knowledge changes in `.knote/config.yaml`, `sources/`, `artifacts/`, and `evals/` when no authorization provider is configured. The permissioned runtime blocks raw diffs because their content is not authorization-bound.
- `/commit [message]` stages only those knowledge paths and creates a commit after confirmation.
- `/versions` lists recent commits, tags, and the current marker.
- `/checkout <ref>` requires confirmation, with an extra dirty-workspace warning.
- The versioned service can read `evals/questions.jsonl`, write `evals/results.jsonl` and `evals/report.md`, and feed the knowledge release gate, but `/eval` is not exposed by the current permissioned runtime because its legacy explain dependency is outside the authorized boundary.
- `/release [tag]` requires a clean workspace and a non-stale eval report with no adapter errors. The repository's product releases use the reviewed GitHub release workflow while permissioned evaluation is unavailable.

## Acceptance

Default validation:

Use Python 3.11 for the Python gates to match CI.

```bash
KNOTE_KAG_FAKE=1 go test ./...
python3 -m unittest discover -s adapters/kag -p '*test*.py'
GOTOOLCHAIN=go1.25.12 go run github.com/openfga/cli/cmd/fga@v0.7.17 model test --tests internal/authz/model/authorization.fga.yaml
python3 tests/smoke/permissioned_graph_real_smoke.py --self-test
CGO_ENABLED=0 go build -o bin/knote ./cmd/knote
PYTHON=/usr/bin/python3 KNOTE_SMOKE_FORCE_BIN=1 scripts/smoke_fake_mvp.sh
```

Manual Eino/OpenAI-compatible validation:

```bash
KNOTE_EINO_BASE_URL=http://127.0.0.1:8317/v1 \
KNOTE_EINO_MODEL=gpt-5.3-codex-spark \
KNOTE_EINO_REASONING_EFFORT=low \
scripts/smoke_eino_local_proxy.sh
```

Manual real KAG validation:

```bash
KNOTE_PYTHON=/path/to/python KNOTE_KAG_HOST=http://127.0.0.1:8887 scripts/smoke_real_kag.sh
```

Manual Phase 2 permissioned graph validation:

```bash
KNOTE_PERMISSIONED_GRAPH_REAL_SMOKE=1 \
KNOTE_PYTHON=/path/to/openspg-kag-0.8-python \
scripts/smoke_permissioned_graph_real.sh
```

## Current Scope

MVP scope includes:

- fullscreen Go TUI
- natural-language and slash command entrypoints
- workspace scan and stable JSONL artifacts
- KAG adapter health/build/query/explain bridge
- session JSONL persistence
- task and permission state
- runtime manager boundary for future TUI/Web reuse
- Eino tool adapters and OpenAI-compatible ADK runner bridge as the only runtime path
- Git diff/log/commit/tag wrappers
- release-oriented CI skeleton
- OpenFGA authorization contracts and a permission-safe graph identity model
- deterministic catalog/projection bundles with exact resource, graph, and Claim bindings
- body-free discovery/retrieve/expand primitives and evidence-only generation
- bounded multi-hop Claim traversal with authorization at every participating hop
- revocation-safe authorized caches, citations, and permission-bound session replay
- protected query surfaces and derived-output visibility enforcement
- credential-free permissioned acceptance tests plus a pinned disposable OpenFGA/OpenSPG live smoke

Out of scope for `v0.2.0`: web UI, desktop app, cloud sync, multi-user collaboration UI, an independent version database, OpenSPG as the serving authorization boundary, default real-CLI composition of the operator permissioned provider, permissioned `/eval`, or an MCP dependency. Main-branch promotion still requires a reviewed release PR, and release tags still require explicit confirmation.
