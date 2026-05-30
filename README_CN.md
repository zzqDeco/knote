# knote

`knote` 是一个面向本地目录知识工作区的 agentic TUI 工具。启动后进入 transcript-first 终端界面，用自然语言和少量 slash command 完成知识库构建、查询、解释、版本化和基础评估。

当前 MVP 调整为 Go-first：

- `cmd/knote`：单一 CLI/TUI binary
- `internal/tui`：Bubble Tea 实现 transcript、composer、overlay、picker、pager、status line
- `internal/runtime`：会话、工具、权限、任务、Git 版本和 KAG 编排
- `adapters/kag`：OpenSPG/KAG Python NDJSON adapter

## 快速开始

```bash
go run ./cmd/knote --workspace tests/fixtures/basic-kb
```

TUI 内可执行：

```text
> /build
> 当前知识库的核心结论是什么？
> /versions
> /diff
> /commit
```

带副作用的命令（`/build`、`/commit`、`/release`、`/checkout`、`/eval`）会先打开内嵌确认提示。按 `Enter` 或 `y` 单次确认，按 `n` 或 `Esc` 取消。

真实 KAG 集成面向 OpenSPG/KAG `0.8.0`。本地未启动 OpenSPG 时，可用 `KNOTE_KAG_FAKE=1` 运行确定性开发模式。

如需指定 Python 解释器，设置 `KNOTE_PYTHON=/path/to/python`。
