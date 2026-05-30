# AGENTS.md

## Project Shape

`knote` is a Go-first TUI and runtime. Do not add Node, pnpm, React, or Ink unless the project direction changes explicitly.

## Architecture

- `cmd/knote` owns CLI flags and starts the TUI.
- `internal/tui` owns Bubble Tea views and interaction state.
- `internal/runtime` owns user intents, tool execution, permission/task/session events, and KAG/Git orchestration.
- `internal/protocol` contains stable event and artifact-facing types.
- `adapters/kag` is the only Python boundary and speaks NDJSON over stdio.

## Rules

- Keep the CLI usable as a single Go binary.
- Keep KAG internals behind the adapter; public knote artifacts must stay stable.
- Keep generated artifacts deterministic and sorted so Git diffs stay readable.
- Side-effecting commands such as `/build`, `/commit`, `/release`, and `/checkout` must flow through explicit runtime actions and permission/confirm state.
