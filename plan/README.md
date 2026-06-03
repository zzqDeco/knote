# knote Plan Index

This directory stores current actionable implementation plans.

## Active Plans

1. `go-tui-mvp.md`
   - Defines the adjusted Go-only MVP implementation, layered runtime refactor, and acceptance checklist.

## MVP PR Sequence

- PR #2: side-effect confirmation contract, merged.
- PR #3: real KAG adapter path, merged.
- PR #4: transcript-first TUI/session UX, merged.
- PR #5: Git version, eval, and release gate UX, merged.
- PR #6: acceptance smoke, documentation, and release-candidate validation, merged.
- PR #7-#13: repository, local store, knowledge, KAG backend, agent/runtime, legacy shim removal, and remote skeleton refactors, merged.
- PR #14: PR #1 actionable review leftovers, merged.
- PR #15: versioned knowledge service, merged.
- PR #16: Eino tools adapter, merged.
- PR #17: runtime manager, merged.
- PR #18: runtime Eino runner skeleton, merged.
- PR #19: architecture/runtime-layer docs.

## Branching

- `main`: releasable branch
- `dev`: integration branch
- feature branches: `feature/*`, `feat/*`, `fix/*`, `refactor/*`, `test/*`, `chore/*`
- release branch: `release/v0.1.0`
