# Architecture

`knote` is a local-first TUI application with a small composition root and layered runtime boundaries:

1. `cmd/knote` parses CLI flags and wires concrete implementations.
2. `internal/tui` owns Bubble Tea projection and keyboard interaction.
3. `internal/runtime` owns Eino-only session/thread lifecycle, event dispatch, task controls, slash routing, confirm routing, and runner management.
4. `internal/knowledge/versioned` owns versioned knowledge operations: build/query/explain/eval/diff/commit/release/checkout/status.
5. `internal/eino/tools` exposes the versioned knowledge service as shallow Eino `InvokableTool` adapters.
6. `internal/runtime/eino` is the Eino ADK runner bridge. It constructs an OpenAI-compatible `ChatModelAgent`, inventories knote tools, and projects ADK events back to knote events.
7. `internal/repository` defines workspace/session/version interfaces; `internal/repository/local` implements them with the local filesystem and Git CLI.
8. `internal/knowledge/kag` owns the OpenSPG/KAG boundary and Python NDJSON adapter subprocess.
9. `internal/repository/remote` is a future adapter skeleton for GitHub/Gitea/GitLab-style backends.

The TUI and runtime are in the same Go binary. The KAG adapter remains a subprocess because OpenSPG/KAG is Python-native and has heavier environment requirements. The stable artifact contract is owned by knote, not by KAG.

## Dependency Flow

```mermaid
flowchart LR
  User["User input"] --> TUI["internal/tui"]
  TUI --> Runtime["internal/runtime"]
  Runtime --> EinoRunner["internal/runtime/eino ADK runner"]
  Runtime --> EinoTools["internal/eino/tools"]
  Runtime --> RepoIf["internal/repository interfaces"]
  EinoRunner --> EinoTools
  EinoTools --> Versioned
  Runtime --> Versioned["internal/knowledge/versioned"]
  Versioned --> RepoIf
  Versioned --> Kag["internal/knowledge/kag"]
  Kag --> Adapter["adapters/kag/knote_kag_adapter.py"]
  Adapter --> OpenSPG["OpenSPG/KAG"]
  RepoIf -. implemented by .-> Local["internal/repository/local"]
  Local --> Sessions[".knote/sessions/*.jsonl"]
  Local --> Config[".knote/config.yaml"]
  Local --> Artifacts["artifacts/*.jsonl"]
  Local --> Evals["evals/*.jsonl"]
  Local --> Git["Git CLI"]
  RepoIf -. future .-> Remote["internal/repository/remote"]
```

`cmd/knote` is the composition root that creates `local.Store`, `kag.Client`, `versioned.Service`, Eino tools, the Eino runner, and `runtime.Manager`. `internal/runtime` does not import the local repository, KAG backend, Python adapter, or TUI.

## Runtime Layers

`internal/runtime` is the interaction boundary for TUI now and Web later. It exposes start, message, confirm, interrupt, task stop, status, subscription, and runner info methods. Runtime owns the active session/thread state, deterministic slash routing, pending side-effect confirmations, and event fanout.

The runtime is Eino-only. Ordinary user messages go through the Eino ADK `ChatModelAgent`; slash commands are routed deterministically by runtime to either local session/status behavior or knote Eino tools. Startup requires an OpenAI-compatible profile and API key from `.knote/config.yaml` plus environment overrides such as `KNOTE_EINO_PROVIDER`, `KNOTE_EINO_MODEL`, `KNOTE_EINO_API_KEY`, `KNOTE_EINO_BASE_URL`, and `KNOTE_EINO_REASONING_EFFORT`. `OPENAI_MODEL`, `OPENAI_API_KEY`, and `OPENAI_BASE_URL` are also accepted. `KNOTE_RUNTIME_MODE=direct` is rejected.

`internal/runtime/eino` holds the Eino-facing runner. It converts knote `InvokableTool` adapters into Eino base tools, constructs the OpenAI-compatible chat model, builds the ADK agent, executes turns through `adk.Runner`, and projects ADK tool/assistant/interrupt events into knote protocol events. It does not own knowledge semantics.

`internal/eino/tools` is intentionally shallow. Each tool parses JSON arguments, calls `internal/knowledge/versioned`, and returns JSON. Mutating tools require a side-effect gate so they cannot bypass runtime confirmation.

Eino side effects are bridged back through runtime confirmation instead of executing directly. In Eino mode, mutating tools call a `SideEffectGate`; runtime stores the pending request, emits one `confirm.request` at a time, and only executes the approved tool once after TUI approval. Queued confirmations are FIFO, request ids include a monotonic suffix, and adapter failures returned by approved build/eval tools are projected as `tool.error`/`error` rather than `tool.complete`.

The local OpenAI-compatible path is validated manually with `scripts/smoke_eino_local_proxy.sh`. That script probes `/v1/models`, starts the Eino-only TUI, sends a PTY prompt, and waits for the model to return `knote-eino-ok`. The smoke is intentionally manual because it depends on a local proxy and API key.

## Runtime And TUI

`internal/tui` owns screen projection only. It keeps the transcript, composer history, overlay state, and status line, then calls runtime methods for every user intent. It does not execute Git, artifact, KAG, Eino, or repository side effects directly.

`internal/runtime` owns the event stream. User messages become `message.user`; read-only slash commands return status, details, settings, versions, or diff events; side-effecting slash commands first emit `confirm.request`. Confirmed actions are validated against runtime-owned pending confirmation state before they can run.

## Session Data

Each session is a JSONL event log under `.knote/sessions/<session-id>.jsonl`. `/clear` appends a `view.clear` event so the TUI projection resets without deleting history. `/new` creates a new session id and emits fresh `gateway.ready` and `session.info` events. `/resume <session-id>` loads the old event log, clears the projection boundary, and appends a new `session.info` event for the resumed session.

## Knowledge And KAG

`internal/knowledge/versioned` implements knote's versioned knowledge semantics:

- `/build` reads sources through `repository.Workspace`, calls `kag.Backend.Build`, normalizes results into knote artifact records, and writes an `ArtifactSet` through the repository.
- Natural-language query and explain prefer KAG, then fall back to stable local summaries when KAG is unavailable or empty.
- `/eval` reads questions through the repository, calls explain, writes stable eval results/report, and updates the knowledge hash used by the release gate.
- Version commands delegate to `repository.Versions`, so Git-backed local versions and future remote-backed versions share the same semantic facade.

`internal/knowledge` remains a compatibility shim over `internal/knowledge/versioned` while old imports are being removed.

`internal/knowledge/kag` talks to `adapters/kag/knote_kag_adapter.py` over newline-delimited JSON on stdio. Public methods are:

- `kag.health`
- `kag.build`
- `kag.query`
- `kag.explain`
- `kag.cancel`

Fake mode is selected with `KNOTE_KAG_FAKE=1` and returns deterministic responses for tests and local development. Real mode expects OpenSPG at `127.0.0.1:8887` by default and `openspg-kag` importable from `KNOTE_PYTHON`. KAG output is normalized into knote-owned artifacts before it becomes part of the public workspace contract.

## Local Repository

`internal/repository/local` implements the repository interfaces for the MVP:

- `.knote/config.yaml`
- `.knote/sessions/*.jsonl`
- `sources/`
- `artifacts/*.jsonl`
- `evals/*.jsonl`
- Git status, diff, log, commit, tag, and checkout

The artifact files are:

- `documents.jsonl`
- `chunks.jsonl`
- `entities.jsonl`
- `relations.jsonl`
- `claims.jsonl`
- `summaries.jsonl`
- `manifest.json`
- `schema.yaml`
- `build_report.md`

JSONL records are sorted by deterministic ids where applicable. Writes use temporary files and rename for atomic replacement. Runtime cache paths under `.knote/cache/`, `.knote/checkpoints/`, `.knote/kag-runtime/`, and `.knote/sessions/` are not knowledge artifacts.

## Remote Repository Skeleton

`internal/repository/remote` is intentionally not wired into `cmd/knote` for v0. It only models the future remote repository boundary and returns `repository.ErrRemoteNotImplemented` for every `Workspace`, `Sessions`, and `Versions` method.

The remote model does not simulate a local dirty working tree. It uses explicit remote concepts:

- base ref
- draft tree
- commit proposal
- pull or merge request
- tag or release

This keeps runtime stable: future remote implementations can make `/commit` create a branch commit or PR without changing TUI command handling.

## Git And Release Gate

The local version implementation scopes version operations to `.knote/config.yaml`, `sources/`, `artifacts/`, and `evals/`. `/commit` stages only these paths. `/release` creates an annotated tag only after:

1. the workspace is clean, ignoring runtime-only session/cache files;
2. `evals/report.md` and `evals/results.jsonl` exist;
3. eval results have no adapter errors;
4. eval results are tied to the current knowledge hash.

The knowledge hash covers `.knote/config.yaml`, `sources/`, `artifacts/`, and `evals/questions.jsonl`, so post-eval knowledge changes make the release gate fail until `/eval` is rerun.
