# knote

`knote` 是一个面向本地目录知识工作区的 agentic TUI 工具。启动后进入 transcript-first 终端界面，用自然语言和少量 slash command 完成知识库构建、查询、解释、版本化和基础评估。

## 版本状态

`v0.1.1` 是已发布的 runtime/Eino 基线。`v0.2.0` 发布线新增 permissioned KAG serving 基础和真实 primitive-provider 路径：基于 OpenFGA 的授权、确定性 projection 与 graph binding、无正文 retrieval primitive、逐跳授权的有界 Claim traversal、可安全撤权的 cache/citation/session replay，以及确定性与真实 OpenFGA/OpenSPG 验收门禁。CLI 当前只在确定性 fake mode 中选择 authorization-aware query tools；默认尚未启用真实 operator runtime composition。

当前 MVP 调整为 Go-first：

- `cmd/knote`：单一 CLI/TUI binary
- `internal/tui`：Bubble Tea 实现 transcript、composer、overlay、picker、pager、status line
- `internal/runtime`：Eino-only session/thread 生命周期、event dispatch、task control、slash routing、confirm routing 和 runner 管理
- `internal/knowledge/versioned`：带版本语义的 build/query/explain/eval/diff/commit/release/checkout/status facade
- `internal/eino/tools`：基于 versioned knowledge facade 的浅层 Eino `InvokableTool` adapter
- `internal/runtime/eino`：OpenAI-compatible Eino ChatModelAgent runner bridge
- `internal/repository/local`：本地 config、session、artifact、eval 和 Git version 实现
- `internal/knowledge/kag`：fake/real OpenSPG/KAG backend 的 Go 边界
- `adapters/kag`：OpenSPG/KAG Python NDJSON adapter

## 快速开始

```bash
CGO_ENABLED=0 go build -o bin/knote ./cmd/knote
KNOTE_KAG_FAKE=1 \
KNOTE_EINO_PROVIDER=openai-compatible \
KNOTE_EINO_MODEL=<model> \
KNOTE_EINO_API_KEY=<api-key> \
KNOTE_EINO_BASE_URL=<openai-compatible-base-url> \
./bin/knote --workspace tests/fixtures/basic-kb
```

`KNOTE_KAG_FAKE=1` 只切换到确定性 KAG adapter；Eino ChatModel runtime 仍然需要 OpenAI-compatible model 配置。

TUI 内可执行：

```text
> /build
> 当前知识库的核心结论是什么？
> /versions
> /diff
> /commit
```

带副作用的命令（`/build`、`/commit`、`/release`、`/checkout`）会先打开内嵌确认提示。按 `Enter` 或 `y` 单次确认，按 `n` 或 `Esc` 取消。`/eval` 当前会 fail closed，因为旧 evaluation 路径依赖非 permissioned explain；在 evaluation 全程经过 authorized evidence boundary 前不会开放。

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
4. 发布候选前在一次性 OpenSPG project 或 stack 上运行 `scripts/smoke_real_kag.sh`；该 compatibility smoke 不会删除服务端 project 数据。

Phase 2 permissioned graph smoke 与上述 legacy compatibility 检查相互独立。它只使用仓库内公开合成 fixture，启动固定版本的临时 OpenFGA/OpenSPG 容器，并在退出时删除容器和 volume：

```bash
KNOTE_PERMISSIONED_GRAPH_REAL_SMOKE=1 \
KNOTE_PYTHON=/path/to/openspg-kag-0.8-python \
scripts/smoke_permissioned_graph_real.sh
```

CI 会运行不需要凭据的确定性部分：`python3 tests/smoke/permissioned_graph_real_smoke.py --self-test`。固定镜像 digest、外部临时 stack 规则和完整阶段说明见 `docs/permissioned-kag-real-smoke.md`。

adapter 会在 `.knote/kag-runtime/` 写入稳定排序的 JSON corpus 和生成的 starter config；需要自定义模型、namespace 或 project 时，把该 config 复制到 `.knote/kag_config.yaml`。KAG runtime 缓存不会进 Git。

## 会话

会话以 JSONL event log 保存在 `.knote/sessions/`。`/clear` 只清空当前 TUI 投影视图，不删除历史；`/new` 创建新 session；`/resume` 列出最近 session；`/resume <session-id>` 在 TUI 中恢复历史。

Permissioned session 还会保存只含元数据的 authorization envelope。只有当前 tenant、knowledge base、principal、authorization model、identity/ACL watermark、task scope 和 consistency preference 全部匹配时才允许 replay；缺失或变化都会在加载历史前 fail closed。撤权会阻止之后的 cache、citation 和 session replay，但无法收回用户已经查看或复制的内容。

## Runtime 分层

TUI 只调用 `internal/runtime`，不直接接触 KAG、Git、repository 或 KAG adapter。runtime 是 Eino-only：slash command 由 runtime 确定性路由，自然语言 turn 通过带 knote tools 的 Eino ADK ChatModelAgent 执行。

```bash
KNOTE_EINO_PROVIDER=openai-compatible \
KNOTE_EINO_MODEL=gpt-4o-mini \
KNOTE_EINO_API_KEY=your-api-key \
KNOTE_EINO_BASE_URL=https://api.openai.com/v1 \
./bin/knote --workspace tests/fixtures/basic-kb
```

`KNOTE_EINO_MODEL_PROFILE` 用于选择 `.knote/config.yaml` 中的模型 profile，默认是 `default`。环境变量会覆盖被选中的 profile。也支持 `OPENAI_MODEL`、`OPENAI_API_KEY`、`OPENAI_BASE_URL`；存在这些覆盖时 provider 默认按 `openai-compatible` 处理。`KNOTE_EINO_REASONING_EFFORT` 支持 `low`、`medium`、`high`。`KNOTE_RUNTIME_MODE=direct` 会被拒绝。

带副作用的 Eino tools 必须经过 runtime side-effect gate，这和 TUI 中 `/build`、`/commit`、`/release`、`/checkout` 的确认规则保持一致。

本地 CLIProxyAPI/OpenAI-compatible smoke 可保持 proxy 运行后执行：

```bash
KNOTE_EINO_BASE_URL=http://127.0.0.1:8317/v1 \
KNOTE_EINO_MODEL=gpt-5.3-codex-spark \
KNOTE_EINO_REASONING_EFFORT=low \
scripts/smoke_eino_local_proxy.sh
```

脚本会先探测 `/v1/models`，再启动 Eino-only TUI，要求模型调用 permissioned `knote_query` tool，并等待 evidence-bound 的 `knote-authorized-ok` 响应。可以显式设置 `KNOTE_EINO_API_KEY`，设置 `KNOTE_CLIPROXY_CONFIG`，或让脚本尝试 `~/.cli-proxy-api/config.yaml`、Homebrew `etc/cliproxyapi.conf` 等 CLIProxyAPI 默认配置路径。

## 版本和评估

`knote` 使用 Git commit 表示知识版本，Git tag 表示发布版本，branch 表示候选实验版本。

- `/diff` 显示 `.knote/config.yaml`、`sources/`、`artifacts/`、`evals/` 的当前知识变更。
- `/commit [message]` 只 stage 上述知识路径，并在确认后提交。
- `/versions` 列出最近 commit、tag 和当前版本标记。
- `/checkout <ref>` 必须确认，dirty workspace 时会显示额外警告。
- Versioned service 可以读取 `evals/questions.jsonl` 并写入 `evals/results.jsonl`、`evals/report.md`，但当前 permissioned runtime 不暴露 `/eval`，因为旧 explain 依赖不在 authorized boundary 内。
- `/release [tag]` 要求 workspace 干净，且最近 eval report 无 adapter error、没有过期。Permissioned evaluation 暂不可用期间，项目产品版本通过已评审的 GitHub release workflow 发布。

## 验收

默认验收命令：

Python 门禁使用 Python 3.11，与 CI 保持一致。

```bash
KNOTE_KAG_FAKE=1 go test ./...
python3 -m unittest discover -s adapters/kag -p '*test*.py'
GOTOOLCHAIN=go1.25.12 go run github.com/openfga/cli/cmd/fga@v0.7.17 model test --tests internal/authz/model/authorization.fga.yaml
python3 tests/smoke/permissioned_graph_real_smoke.py --self-test
CGO_ENABLED=0 go build -o bin/knote ./cmd/knote
PYTHON=/usr/bin/python3 KNOTE_SMOKE_FORCE_BIN=1 scripts/smoke_fake_mvp.sh
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

Phase 2 permissioned graph 手动验收：

```bash
KNOTE_PERMISSIONED_GRAPH_REAL_SMOKE=1 \
KNOTE_PYTHON=/path/to/openspg-kag-0.8-python \
scripts/smoke_permissioned_graph_real.sh
```

## 当前范围

`v0.2.0` 包含 OpenFGA 授权契约、确定性 catalog/projection bundle、精确 resource/graph/Claim binding、无正文 discover/retrieve/expand、只接收已授权 evidence 的 generate、有界逐跳 Claim traversal、可安全撤权的 cache/citation/session replay、受保护查询面，以及确定性与真实 permissioned acceptance。

`v0.2.0` 不包含 web UI、desktop app、cloud sync、多用户协作 UI、独立版本数据库、把 OpenSPG 作为 serving 授权边界、默认真实 CLI operator-provider composition、permissioned `/eval`，或 MCP 依赖。推进 `main` 仍必须经过已评审的 release PR，创建 release tag 仍需要明确确认。
