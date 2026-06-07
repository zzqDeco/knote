# knote

`knote` 是一个面向本地目录知识工作区的 agentic TUI 工具。启动后进入 transcript-first 终端界面，用自然语言和少量 slash command 完成知识库构建、查询、解释、版本化和基础评估。

当前 MVP 调整为 Go-first：

- `cmd/knote`：单一 CLI/TUI binary
- `internal/tui`：Bubble Tea 实现 transcript、composer、overlay、picker、pager、status line
- `internal/runtime`：session/thread 生命周期、event dispatch、task control、confirm routing 和 runner 选择
- `internal/agent`：direct runner 的 turn、slash command、确认、任务和 session event
- `internal/knowledge/versioned`：带版本语义的 build/query/explain/eval/diff/commit/release/checkout/status facade
- `internal/eino/tools`：基于 versioned knowledge facade 的浅层 Eino `InvokableTool` adapter
- `internal/runtime/eino`：OpenAI-compatible Eino ChatModelAgent runner bridge；默认仍使用 direct runner
- `internal/repository/local`：本地 config、session、artifact、eval 和 Git version 实现
- `internal/knowledge/kag`：fake/real OpenSPG/KAG backend 的 Go 边界
- `adapters/kag`：OpenSPG/KAG Python NDJSON adapter

## 快速开始

```bash
CGO_ENABLED=0 go build -o bin/knote ./cmd/knote
KNOTE_KAG_FAKE=1 ./bin/knote --workspace tests/fixtures/basic-kb
```

TUI 内可执行：

```text
> /build
> 当前知识库的核心结论是什么？
> /versions
> /diff
> /commit
> /eval
```

带副作用的命令（`/build`、`/commit`、`/release`、`/checkout`、`/eval`）会先打开内嵌确认提示。按 `Enter` 或 `y` 单次确认，按 `n` 或 `Esc` 取消。

常用启动参数：

```bash
./bin/knote --workspace <path>
./bin/knote --resume <session-id>
./bin/knote --version
./bin/knote --help
```

## KAG 模式

真实 KAG 集成面向 OpenSPG/KAG `0.8.0`。本地未启动 OpenSPG 时，可用 `KNOTE_KAG_FAKE=1` 运行确定性开发模式。

```bash
KNOTE_KAG_FAKE=1 go test ./...
scripts/smoke_fake_mvp.sh
```

`scripts/smoke_fake_mvp.sh` 会优先复用已有的 `bin/knote`；如需验证其他 binary，可设置 `KNOTE_BIN=/path/to/knote`。macOS 下默认用 `go run` 驱动 PTY，避免本机未签名 binary 偶发启动卡住；如需强制验证已构建 binary，设置 `KNOTE_SMOKE_FORCE_BIN=1`。

如需指定 Python 解释器，设置 `KNOTE_PYTHON=/path/to/python`。

真实 KAG 执行需要：

1. 本机 OpenSPG 服务运行在 `http://127.0.0.1:8887`。
2. `KNOTE_PYTHON` 指向的 Python 环境已安装 `openspg-kag`。
3. Markdown 或 text 源文件放在 `sources/` 下。
4. 发布候选前运行 `scripts/smoke_real_kag.sh`。

adapter 会在 `.knote/kag-runtime/` 写入稳定排序的 JSON corpus 和生成的 starter config；需要自定义模型、namespace 或 project 时，把该 config 复制到 `.knote/kag_config.yaml`。KAG runtime 缓存不会进 Git。

## 会话

会话以 JSONL event log 保存在 `.knote/sessions/`。`/clear` 只清空当前 TUI 投影视图，不删除历史；`/new` 创建新 session；`/resume` 列出最近 session；`/resume <session-id>` 在 TUI 中恢复历史。

## Runtime 分层

TUI 只调用 `internal/runtime`，不直接接触 KAG、Git、repository 或 Eino。默认生产路径仍使用 direct agent runner。设置 `KNOTE_RUNTIME_MODE=eino` 后，会启动基于 OpenAI-compatible chat model 的 Eino ADK ChatModelAgent 路径：

```bash
KNOTE_RUNTIME_MODE=eino \
KNOTE_EINO_PROVIDER=openai-compatible \
KNOTE_EINO_MODEL=gpt-4o-mini \
KNOTE_EINO_API_KEY=your-api-key \
KNOTE_EINO_BASE_URL=https://api.openai.com/v1 \
./bin/knote --workspace tests/fixtures/basic-kb
```

`KNOTE_EINO_MODEL_PROFILE` 用于选择 `.knote/config.yaml` 中的模型 profile，默认是 `default`。环境变量会覆盖被选中的 profile。`KNOTE_EINO_REASONING_EFFORT` 支持 `low`、`medium`、`high`。

带副作用的 Eino tools 必须经过 runtime side-effect gate，这和 TUI 中 `/build`、`/commit`、`/release`、`/checkout`、`/eval` 的确认规则保持一致。

本地 CLIProxyAPI/OpenAI-compatible smoke 可保持 proxy 运行后执行：

```bash
KNOTE_EINO_BASE_URL=http://127.0.0.1:8317/v1 \
KNOTE_EINO_MODEL=gpt-5.3-codex-spark \
KNOTE_EINO_REASONING_EFFORT=low \
scripts/smoke_eino_local_proxy.sh
```

脚本会先探测 `/v1/models`，再以 `KNOTE_RUNTIME_MODE=eino` 启动 TUI，通过 PTY 发送固定 prompt，并等待返回 `knote-eino-ok`。可以显式设置 `KNOTE_EINO_API_KEY`；如果本机有 `KNOTE_CLIPROXY_CONFIG` 指向的 CLIProxyAPI config，脚本会尝试读取第一条 `api-keys`，但不会打印 key。

## 版本和评估

`knote` 使用 Git commit 表示知识版本，Git tag 表示发布版本，branch 表示候选实验版本。

- `/diff` 显示 `.knote/config.yaml`、`sources/`、`artifacts/`、`evals/` 的当前知识变更。
- `/commit [message]` 只 stage 上述知识路径，并在确认后提交。
- `/versions` 列出最近 commit、tag 和当前版本标记。
- `/checkout <ref>` 必须确认，dirty workspace 时会显示额外警告。
- `/eval` 读取 `evals/questions.jsonl`，不存在时使用内置 smoke question，并写入 `evals/results.jsonl` 和 `evals/report.md`。
- `/release [tag]` 要求 workspace 干净，且最近 eval report 无 adapter error、没有过期。

## 验收

默认验收命令：

```bash
KNOTE_KAG_FAKE=1 go test ./...
python3 -m unittest discover -s adapters/kag -p '*test*.py'
CGO_ENABLED=0 go build -o bin/knote ./cmd/knote
scripts/smoke_fake_mvp.sh
```

手动 Eino/OpenAI-compatible 验收：

```bash
KNOTE_EINO_BASE_URL=http://127.0.0.1:8317/v1 \
KNOTE_EINO_MODEL=gpt-5.3-codex-spark \
KNOTE_EINO_REASONING_EFFORT=low \
scripts/smoke_eino_local_proxy.sh
```

真实 KAG 手动验收：

```bash
KNOTE_PYTHON=/path/to/python KNOTE_KAG_HOST=http://127.0.0.1:8887 scripts/smoke_real_kag.sh
```
