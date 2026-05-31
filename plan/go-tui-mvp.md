# Go TUI MVP

## Summary

The MVP is a single Go CLI/TUI binary with a Python KAG subprocess adapter. Bubble Tea replaces the previous TypeScript/Ink plan so `knote` has no Node or pnpm dependency.

## Implementation

- `cmd/knote` parses `--workspace`, `--resume`, `--version`, and starts the TUI.
- `internal/tui` renders transcript, composer, permission overlay, tasks, versions, diff pager, and status line.
- `internal/runtime` maps user messages and slash commands to build/query/explain/status/version/eval actions.
- Side-effecting slash commands emit `confirm.request` and run only after TUI approval.
- `internal/artifact` writes deterministic JSONL and Markdown artifacts.
- `internal/kag` speaks NDJSON with `adapters/kag/knote_kag_adapter.py`.
- `internal/gitstore` wraps read-only Git status/log/diff plus confirmed commit/tag/checkout.

## Acceptance

- `go test ./...` passes.
- `go run ./cmd/knote --workspace tests/fixtures/basic-kb` opens the TUI.
- `KNOTE_KAG_FAKE=1` enables deterministic KAG build/query/explain without OpenSPG.
