# Go TUI MVP

## Summary

The MVP is a single Go CLI/TUI binary with a Python KAG subprocess adapter. Bubble Tea replaces the previous TypeScript/Ink plan so `knote` has no Node or pnpm dependency.

## Implementation

- `cmd/knote` parses `--workspace`, `--resume`, `--version`, and starts the TUI.
- `internal/tui` renders transcript, composer, permission overlay, tasks, versions, diff pager, and status line.
- `internal/agent` maps user messages and slash commands to build/query/explain/status/version/eval actions.
- Side-effecting slash commands emit `confirm.request` and run only after TUI approval.
- `internal/knowledge` owns build/query/explain/eval semantics and normalizes stable knote artifacts.
- `internal/repository/local` writes deterministic JSONL/Markdown artifacts, sessions, evals, config, and Git versions.
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
- PR F `refactor/remove-legacy-shims`: removes compatibility shims and updates docs/tests so new code depends on `agent`, `knowledge`, and `repository` boundaries.

## Acceptance

- `KNOTE_KAG_FAKE=1 go test ./...` passes.
- `python3 -m unittest discover -s adapters/kag -p '*test*.py'` passes.
- `CGO_ENABLED=0 go build -o bin/knote ./cmd/knote` succeeds.
- `scripts/smoke_fake_mvp.sh` starts the TUI in a PTY, runs fake build/query/diff/commit/resume/eval, and exits cleanly.
- `KNOTE_PYTHON=/path/to/python KNOTE_KAG_HOST=http://127.0.0.1:8887 scripts/smoke_real_kag.sh` passes in a local real OpenSPG/KAG environment.

## Release Candidate Checklist

1. Merge PR #6 into `dev` after CI and Codex review are clean enough for MVP.
2. Create `release/v0.1.0` from `dev`.
3. Run the acceptance commands above locally, including real KAG smoke.
4. Promote `release/v0.1.0` to `main` only after explicit confirmation.
5. Tag `v0.1.0` only after explicit confirmation.
