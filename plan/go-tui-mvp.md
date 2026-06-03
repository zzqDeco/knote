# Go TUI MVP

## Summary

The MVP is a single Go CLI/TUI binary with a Python KAG subprocess adapter. Bubble Tea replaces the previous TypeScript/Ink plan so `knote` has no Node or pnpm dependency.

## Implementation

- `cmd/knote` parses `--workspace`, `--resume`, `--version`, and starts the TUI.
- `internal/tui` renders transcript, composer, permission overlay, tasks, versions, diff pager, and status line.
- `internal/runtime` manages session/thread lifecycle, event dispatch, task controls, confirm routing, and runner selection.
- `internal/agent` maps direct-runner user messages and slash commands to build/query/explain/status/version/eval actions.
- Side-effecting slash commands emit `confirm.request` and run only after TUI approval.
- `internal/knowledge/versioned` owns versioned build/query/explain/eval/version semantics and normalizes stable knote artifacts.
- `internal/eino/tools` exposes versioned knowledge as shallow Eino tools.
- `internal/runtime/eino` is an unwired Eino runner skeleton for tool inventory and future ADK runner activation.
- `internal/repository/local` writes deterministic JSONL/Markdown artifacts, sessions, evals, config, and Git versions.
- `internal/repository/remote` is an unwired future adapter skeleton that returns `ErrRemoteNotImplemented`.
- `internal/knowledge/kag` speaks NDJSON with `adapters/kag/knote_kag_adapter.py`.
- `adapters/kag` prepares sorted corpus JSON, generates a starter `kag_config.yaml`, and invokes real KAG builder/solver APIs when OpenSPG/KAG is installed and reachable.

## PR Progress

- PR #2 `feature/confirm-side-effects`: completed and merged to `dev`.
- PR #3 `feature/kag-real-adapter`: completed and merged to `dev`.
- PR #4 `feature/tui-session-ux`: completed and merged to `dev`.
- PR #5 `feature/version-eval-release-gate`: completed and merged to `dev`.
- PR #6 `test/mvp-acceptance-docs`: completed and merged to `dev`.
- PR #7 `refactor/repository-interfaces`: completed and merged to `dev`.
- PR #8 `refactor/local-repository`: completed and merged to `dev`.
- PR #9 `refactor/knowledge-service`: completed and merged to `dev`.
- PR #10 `refactor/kag-backend`: completed and merged to `dev`.
- PR #11 `refactor/agent-runtime`: completed and merged to `dev`.
- PR #12 `refactor/remove-legacy-shims`: completed and merged to `dev`.
- PR #13 `refactor/remote-repository-skeleton`: completed and merged to `dev`.
- PR #14 `fix/review-1-leftovers`: completed and merged to `dev`.
- PR #15 `refactor/versioned-knowledge-service`: completed and merged to `dev`.
- PR #16 `refactor/eino-tools-adapter`: completed and merged to `dev`.
- PR #17 `refactor/runtime-manager`: completed and merged to `dev`.
- PR #18 `refactor/runtime-eino-runner-skeleton`: completed and merged to `dev`.
- PR #19 `docs/architecture-runtime-layers`: documents the current layered runtime architecture and validation gates.

## Acceptance

- `KNOTE_KAG_FAKE=1 go test ./...` passes.
- `/usr/bin/python3 -m unittest discover -s adapters/kag -p '*test*.py'` passes.
- `CGO_ENABLED=0 go build -o bin/knote ./cmd/knote` succeeds.
- `PYTHON=/usr/bin/python3 KNOTE_SMOKE_FORCE_BIN=1 bash scripts/smoke_fake_mvp.sh` starts the TUI in a PTY, runs fake build/query/diff/commit/resume/eval, and exits cleanly.
- `KNOTE_PYTHON=/path/to/python KNOTE_KAG_HOST=http://127.0.0.1:8887 scripts/smoke_real_kag.sh` passes in a local real OpenSPG/KAG environment.

## Release Candidate Checklist

1. Keep all refactor/docs PRs flowing through `dev`.
2. Run the acceptance commands above locally, including real KAG smoke for release candidates.
3. Promote release branches to `main` only after explicit confirmation.
4. Create release tags only after explicit confirmation.
