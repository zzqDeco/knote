# Architecture

`knote` is a local-first TUI application with three runtime layers:

1. Go TUI (`internal/tui`)
2. Go runtime and tools (`internal/runtime`)
3. Python KAG adapter (`adapters/kag`)

The TUI and runtime are in the same binary for the MVP. The KAG adapter remains a subprocess because OpenSPG/KAG is Python-native and has heavier environment requirements.

The stable artifact contract is owned by knote, not by KAG.
