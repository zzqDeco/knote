# knote

`knote` is a local knowledge-workspace agentic TUI. It opens a transcript-first terminal interface in the current directory and helps build, query, version, and evaluate a local knowledge base.

This MVP is Go-first:

- `cmd/knote`: single CLI/TUI binary
- `internal/tui`: Bubble Tea transcript, composer, overlays, pickers, and status line
- `internal/runtime`: session, tools, permissions, task state, Git versioning, and KAG orchestration
- `adapters/kag`: Python NDJSON adapter for OpenSPG/KAG

## Quick Start

```bash
go run ./cmd/knote --workspace tests/fixtures/basic-kb
```

Inside the TUI:

```text
> /build
> 当前知识库的核心结论是什么？
> /versions
> /diff
> /commit
```

Side-effecting commands (`/build`, `/commit`, `/release`, `/checkout`, `/eval`) open an inline confirmation prompt. Press `Enter` or `y` to approve once, and `n` or `Esc` to cancel.

## KAG

The Python adapter is designed for OpenSPG/KAG `0.8.0`. For local development without OpenSPG running, set `KNOTE_KAG_FAKE=1` to use the adapter's deterministic fixture mode.

```bash
KNOTE_KAG_FAKE=1 go test ./...
```

If your preferred Python is not the system interpreter, set `KNOTE_PYTHON=/path/to/python`.

For real KAG execution, start OpenSPG locally at `http://127.0.0.1:8887`, install `openspg-kag` in the Python environment used by `KNOTE_PYTHON`, and put Markdown or text sources under `sources/`. The adapter writes a sorted JSON corpus and generated starter config under `.knote/kag-runtime/`; copy that config to `.knote/kag_config.yaml` when you need custom model, namespace, or project settings. Runtime KAG cache is ignored by Git.

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
