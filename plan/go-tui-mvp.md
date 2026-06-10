# Go TUI MVP

## Summary

The MVP is a single Go CLI/TUI binary with a Python KAG subprocess adapter. Bubble Tea replaces the previous TypeScript/Ink plan so `knote` has no Node or pnpm dependency.

## Implementation

- `cmd/knote` parses `--workspace`, `--resume`, `--version`, and starts the TUI.
- `internal/tui` renders transcript, composer, permission overlay, tasks, versions, diff pager, and status line.
- `internal/runtime` manages Eino-only session/thread lifecycle, event dispatch, task controls, slash routing, confirm routing, and runner management.
- Side-effecting slash commands emit `confirm.request` and run only after TUI approval.
- `internal/knowledge/versioned` owns versioned build/query/explain/eval/version semantics and normalizes stable knote artifacts.
- `internal/eino/tools` exposes versioned knowledge as shallow Eino tools.
- `internal/runtime/eino` is the Eino ADK runner bridge for OpenAI-compatible ChatModelAgent execution and tool inventory.
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
- PR #20 `feature/eino-direct-runner-bridge`: completed and merged to `dev`.
- PR #21 `feature/eino-chatmodel-agent`: completed and merged to `dev`.
- PR #22 `feature/eino-confirmation-bridge`: completed and merged to `dev`.
- PR #23 `test/eino-runtime-acceptance-docs`: adds repeatable Eino local proxy smoke coverage and updates runtime acceptance docs.
- PR #24 `fix/eino-smoke-portability`: completed and merged to `dev`.
- PR #25 `docs/release-v0.1.1-readiness`: prepares `v0.1.1` release-candidate documentation.
- PR #30 `refactor/eino-only-runtime`: completed and merged to `dev`.
- PR #31 `refactor/remove-direct-agent`: removes the legacy direct agent package and updates Eino-only docs.

## Acceptance

- `KNOTE_KAG_FAKE=1 go test ./...` passes.
- `/usr/bin/python3 -m unittest discover -s adapters/kag -p '*test*.py'` passes.
- `CGO_ENABLED=0 go build -o bin/knote ./cmd/knote` succeeds.
- `PYTHON=/usr/bin/python3 KNOTE_SMOKE_FORCE_BIN=1 bash scripts/smoke_fake_mvp.sh` starts the TUI in a PTY, runs fake build/diff/commit/resume/eval, and exits cleanly. `go test ./...` also covers the `knote_query` Eino tool against fake KAG.
- `KNOTE_EINO_BASE_URL=http://127.0.0.1:8317/v1 KNOTE_EINO_MODEL=gpt-5.3-codex-spark KNOTE_EINO_REASONING_EFFORT=low bash scripts/smoke_eino_local_proxy.sh` manually validates the OpenAI-compatible Eino runner path when a local proxy and API key are available.
- `KNOTE_PYTHON=/path/to/python KNOTE_KAG_HOST=http://127.0.0.1:8887 scripts/smoke_real_kag.sh` passes in a local real OpenSPG/KAG environment.

## Release Candidate Checklist

1. Keep all refactor/docs PRs flowing through `dev`.
2. Run the acceptance commands above locally, including real KAG smoke for release candidates.
3. Promote release branches to `main` only after explicit confirmation.
4. Create release tags only after explicit confirmation.

## v0.1.1 Release Candidate

`v0.1.1` is the post-`v0.1.0` runtime/Eino release candidate. It uses the Eino ChatModel path as the only runtime, keeps the Eino mutating-tool confirmation bridge, and includes local CLIProxyAPI/OpenAI-compatible smoke plus hardened smoke portability.

Candidate validation must pass on `dev` and again on `release/v0.1.1`:

- `KNOTE_KAG_FAKE=1 go test ./...`
- `/usr/bin/python3 -m unittest discover -s adapters/kag -p '*test*.py'`
- `CGO_ENABLED=0 go build -o bin/knote ./cmd/knote`
- `PYTHON=/usr/bin/python3 KNOTE_SMOKE_FORCE_BIN=1 bash scripts/smoke_fake_mvp.sh`
- `KNOTE_EINO_BASE_URL=http://127.0.0.1:8317/v1 KNOTE_EINO_MODEL=gpt-5.3-codex-spark KNOTE_EINO_REASONING_EFFORT=low bash scripts/smoke_eino_local_proxy.sh`
- `KNOTE_PYTHON=/path/to/kag-venv/python KNOTE_KAG_HOST=http://127.0.0.1:8887 bash scripts/smoke_real_kag.sh`

After these pass, create `release/v0.1.1` from `dev`, open `release/v0.1.1 -> main`, and trigger `@codex review`. Merging to `main`, creating `v0.1.1`, and publishing release assets require separate explicit confirmation.
