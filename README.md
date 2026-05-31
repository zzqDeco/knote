# knote

`knote` is a local knowledge-workspace agentic TUI. It opens a transcript-first terminal interface in the current directory and helps build, query, version, and evaluate a local knowledge base.

This MVP is Go-first:

- `cmd/knote`: single CLI/TUI binary
- `internal/tui`: Bubble Tea transcript, composer, overlays, pickers, and status line
- `internal/runtime`: session, tools, permissions, task state, Git versioning, and KAG orchestration
- `adapters/kag`: Python NDJSON adapter for OpenSPG/KAG

## Quick Start

```bash
CGO_ENABLED=0 go build -o bin/knote ./cmd/knote
KNOTE_KAG_FAKE=1 ./bin/knote --workspace tests/fixtures/basic-kb
```

Inside the TUI:

```text
> /build
> 当前知识库的核心结论是什么？
> /versions
> /diff
> /commit
> /eval
```

Side-effecting commands (`/build`, `/commit`, `/release`, `/checkout`, `/eval`) open an inline confirmation prompt. Press `Enter` or `y` to approve once, and `n` or `Esc` to cancel.

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
4. Run `scripts/smoke_real_kag.sh` before a release candidate.

The adapter writes a sorted JSON corpus and generated starter config under `.knote/kag-runtime/`; copy that config to `.knote/kag_config.yaml` when you need custom model, namespace, or project settings. Runtime KAG cache is ignored by Git.

## Sessions

Sessions are JSONL event logs under `.knote/sessions/`. `/clear` only clears the current TUI projection; it does not delete session history. `/new` creates a fresh session. `/resume` lists recent sessions, and `/resume <session-id>` replays one in the TUI.

## Versions And Eval

`knote` treats Git commits as knowledge versions, Git tags as release versions, and branches as candidate experiments.

- `/diff` shows current knowledge changes in `.knote/config.yaml`, `sources/`, `artifacts/`, and `evals/`.
- `/commit [message]` stages only those knowledge paths and creates a commit after confirmation.
- `/versions` lists recent commits, tags, and the current marker.
- `/checkout <ref>` requires confirmation, with an extra dirty-workspace warning.
- `/eval` reads `evals/questions.jsonl` or uses an internal smoke question, writes `evals/results.jsonl` and `evals/report.md`, and feeds the release gate.
- `/release [tag]` requires a clean workspace and a non-stale eval report with no adapter errors.

## Acceptance

Default validation:

```bash
KNOTE_KAG_FAKE=1 go test ./...
python3 -m unittest discover -s adapters/kag -p '*test*.py'
CGO_ENABLED=0 go build -o bin/knote ./cmd/knote
scripts/smoke_fake_mvp.sh
```

Manual real KAG validation:

```bash
KNOTE_PYTHON=/path/to/python KNOTE_KAG_HOST=http://127.0.0.1:8887 scripts/smoke_real_kag.sh
```

## Current Scope

MVP scope includes:

- fullscreen Go TUI
- natural-language and slash command entrypoints
- workspace scan and stable JSONL artifacts
- KAG adapter health/build/query/explain bridge
- session JSONL persistence
- task and permission state
- Git diff/log/commit/tag wrappers
- release-oriented CI skeleton

Not in v0.1.0: web UI, desktop app, cloud sync, multi-user collaboration, independent version database, graph-database versioning, or MCP dependency.
