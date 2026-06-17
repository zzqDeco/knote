#!/usr/bin/env python3
"""knote OpenSPG/KAG NDJSON adapter.

The adapter keeps KAG-specific behavior behind a stable knote protocol. It has
an explicit fake mode for deterministic local tests:

    KNOTE_KAG_FAKE=1 python3 adapters/kag/knote_kag_adapter.py
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from ipaddress import ip_address
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Any
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest


def emit(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def result(req_id: str, data: dict[str, Any], message: str = "") -> None:
    emit({"id": req_id, "type": "result", "message": message, "data": data})


def progress(req_id: str, message: str, current: int = 0, total: int = 0) -> None:
    emit(
        {
            "id": req_id,
            "type": "progress",
            "message": message,
            "data": {"current": current, "total": total},
        }
    )


def error(req_id: str, message: str) -> None:
    emit({"id": req_id, "type": "error", "error": message})


BUILD_SUMMARY_RE = re.compile(
    r"Done process\s+(?P<total>\d+)\s+records,\s+with\s+(?P<success>\d+)\s+successfully processed and\s+(?P<failures>\d+)\s+failures? encountered",
    re.IGNORECASE,
)
CONFIG_TEMPLATE_RE = re.compile(
    r"\{\{\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:\s*\|\s*default\(\s*(?P<default>[^)]*)\s*\))?\s*\}\}"
)


def capture_stdout(fn: Any, *args: Any, **kwargs: Any) -> tuple[Any, str]:
    captured = StringIO()
    with redirect_stdout(captured):
        value = fn(*args, **kwargs)
    output = captured.getvalue()
    if output:
        sys.stderr.write(output)
        sys.stderr.flush()
    return value, output


def run_capturing_stdout(fn: Any, *args: Any, **kwargs: Any) -> Any:
    value, _ = capture_stdout(fn, *args, **kwargs)
    return value


def parse_build_summary(output: str) -> dict[str, int] | None:
    match = BUILD_SUMMARY_RE.search(output)
    if not match:
        return None
    return {key: int(value) for key, value in match.groupdict().items()}


def ensure_successful_build_summary(summary: dict[str, int] | None) -> None:
    if not summary:
        raise RuntimeError("KAG build did not report a parseable success summary")
    if summary["failures"] == 0 and summary["success"] > 0:
        return
    raise RuntimeError(
        "KAG build failed for "
        f"{summary['failures']} of {summary['total']} records "
        f"({summary['success']} succeeded)"
    )


def workspace_path(params: dict[str, Any]) -> Path:
    return Path(params.get("workspace") or ".").resolve()


def runtime_dir(params: dict[str, Any]) -> Path:
    value = params.get("runtime_dir")
    if value:
        path = Path(value)
        if not path.is_absolute():
            path = workspace_path(params) / path
        return path.resolve()
    return workspace_path(params) / ".knote" / "kag-runtime"


def source_files(workspace: Path) -> list[Path]:
    roots = [workspace / "sources"]
    files: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in {".md", ".txt"}:
                files.append(path)
    return sorted(files, key=lambda p: p.relative_to(workspace).as_posix())


def title_from_content(content: str, fallback: str) -> str:
    for line in content.splitlines():
        title = line.strip().lstrip("#").strip()
        if title:
            return title
    return fallback


def explicit_corpus_records(params: dict[str, Any]) -> list[dict[str, Any]] | None:
    corpus = params.get("corpus")
    if corpus is None:
        return None
    if not isinstance(corpus, list):
        raise RuntimeError("corpus must be a list of records")
    records: list[dict[str, Any]] = []
    for index, item in enumerate(corpus):
        if not isinstance(item, dict):
            raise RuntimeError(f"corpus[{index}] must be an object")
        content = str(item.get("content") or "")
        if not content.strip():
            raise RuntimeError(f"corpus[{index}].content is required")
        source_path = str(item.get("source_path") or item.get("path") or f"corpus/{index + 1}.txt")
        records.append(
            {
                "id": str(item.get("id") or source_path),
                "name": str(item.get("name") or title_from_content(content, source_path)),
                "content": content,
                "source_path": source_path,
            }
        )
    return records


def prepare_corpus(workspace: Path, out_dir: Path, params: dict[str, Any] | None = None) -> tuple[Path, list[dict[str, Any]]]:
    params = params or {}
    explicit = explicit_corpus_records(params)
    records: list[dict[str, Any]] = []
    if explicit is not None:
        records = explicit
    else:
        files = source_files(workspace)
        for path in files:
            rel = path.relative_to(workspace).as_posix()
            content = path.read_text(encoding="utf-8")
            records.append(
                {
                    "id": rel,
                    "name": title_from_content(content, rel),
                    "content": content,
                    "source_path": rel,
                }
            )
    out_dir.mkdir(parents=True, exist_ok=True)
    ensure_runtime_excluded(workspace, out_dir)
    corpus_path = out_dir / "corpus.json"
    atomic_write_text(corpus_path, json.dumps(records, ensure_ascii=False, indent=2) + "\n")
    return corpus_path, records


def ensure_runtime_excluded(workspace: Path, out_dir: Path) -> None:
    workspace = workspace.resolve()
    out_dir = out_dir.resolve()
    repo_info = git_repo_info(workspace)
    if repo_info is None:
        return
    repo_root, exclude_path = repo_info
    try:
        rel = out_dir.relative_to(repo_root).as_posix().rstrip("/")
    except ValueError:
        return
    if not rel:
        return
    pattern = f"/{rel}/"
    exclude_path.parent.mkdir(parents=True, exist_ok=True)
    existing = exclude_path.read_text(encoding="utf-8") if exclude_path.exists() else ""
    if pattern in {line.strip() for line in existing.splitlines()}:
        return
    suffix = "" if existing.endswith("\n") or existing == "" else "\n"
    with exclude_path.open("a", encoding="utf-8") as handle:
        handle.write(f"{suffix}# knote runtime cache\n{pattern}\n")


def git_repo_info(workspace: Path) -> tuple[Path, Path] | None:
    current = workspace.resolve()
    for repo_root in [current, *current.parents]:
        git_path = repo_root / ".git"
        if git_path.is_dir():
            return repo_root, git_path / "info" / "exclude"
        if not git_path.is_file():
            continue
        text = git_path.read_text(encoding="utf-8").strip()
        prefix = "gitdir:"
        if not text.startswith(prefix):
            continue
        git_dir = Path(text[len(prefix) :].strip())
        if not git_dir.is_absolute():
            git_dir = repo_root / git_dir
        return repo_root, git_dir / "info" / "exclude"
    return None


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def select_config(params: dict[str, Any], out_dir: Path, *, generate: bool = True) -> Path:
    workspace = workspace_path(params)
    explicit = params.get("config_path")
    if explicit:
        path = Path(explicit)
        candidate = path if path.is_absolute() else workspace / path
        if not candidate.exists():
            raise FileNotFoundError(f"explicit KAG config not found: {candidate}")
        return candidate.resolve()
    candidates = [workspace / ".knote" / "kag_config.yaml", workspace / "kag_config.yaml"]
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    generated = out_dir / "kag_config.yaml"
    if generated.exists():
        if generate:
            ensure_runtime_excluded(workspace, out_dir)
            generate_kag_config(generated, params)
        return generated.resolve()
    if not generate:
        raise FileNotFoundError("KAG config not found; run /build first or provide config_path")
    ensure_runtime_excluded(workspace, out_dir)
    generate_kag_config(generated, params)
    return generated


def config_host(config_path: Path) -> str:
    if not config_path.exists():
        return ""
    for line in config_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith("host_addr:"):
            continue
        value = stripped.split(":", 1)[1].strip()
        return resolve_config_value(value)
    return ""


def resolve_config_value(value: str) -> str:
    value = value.strip().strip("'\"")
    if value.startswith("!ENV "):
        return os.environ.get(value[5:].strip(), "")
    match = CONFIG_TEMPLATE_RE.fullmatch(value)
    if match:
        env_value = os.environ.get(match.group("name"))
        if env_value:
            return env_value
        default = match.group("default")
        if default is not None:
            return default.strip().strip("'\"")
        return ""
    return value


def split_no_proxy(value: str) -> list[str]:
    return [entry.strip() for entry in value.split(",") if entry.strip()]


def no_proxy_key(entry: str) -> str:
    return entry.strip().lower()


def no_proxy_entries() -> list[str]:
    entries: list[str] = []
    seen: set[str] = set()
    for env_name in ("NO_PROXY", "no_proxy"):
        for entry in split_no_proxy(os.environ.get(env_name, "")):
            key = no_proxy_key(entry)
            if key in seen:
                continue
            entries.append(entry)
            seen.add(key)
    return entries


def endpoint_host(value: str) -> str:
    value = resolve_config_value(value).strip()
    if not value:
        return ""
    parsed = urlparse.urlparse(value)
    if not parsed.hostname and "://" not in value:
        parsed = urlparse.urlparse("//" + value)
    return (parsed.hostname or "").strip().strip("[]").rstrip(".")


def local_no_proxy_host(host: str) -> bool:
    host = host.strip().strip("[]").rstrip(".").lower()
    if not host:
        return False
    if host == "localhost" or host.endswith(".local"):
        return True
    try:
        addr = ip_address(host)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_private or addr.is_link_local


def config_endpoint_values(config_path: Path) -> list[str]:
    if not config_path.exists():
        return []
    values: list[str] = []
    for line in config_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith(("host_addr:", "base_url:")):
            values.append(stripped.split(":", 1)[1].strip())
    return values


def local_no_proxy_entries(params: dict[str, Any], config_path: Path | None = None) -> list[str]:
    values: list[str] = [
        "localhost",
        "127.0.0.1",
        "::1",
        str(params.get("host") or ""),
        str(params.get("openie_llm_base_url") or ""),
        str(params.get("chat_llm_base_url") or ""),
        str(params.get("vector_base_url") or ""),
        os.environ.get("KNOTE_OPENIE_LLM_BASE_URL", ""),
        os.environ.get("KNOTE_CHAT_LLM_BASE_URL", ""),
        os.environ.get("KNOTE_VECTOR_BASE_URL", ""),
    ]
    if config_path is not None:
        values.extend(config_endpoint_values(config_path))

    entries: list[str] = []
    seen: set[str] = set()
    for value in values:
        host = endpoint_host(value)
        if not host and value in {"localhost", "127.0.0.1", "::1"}:
            host = value
        if not local_no_proxy_host(host):
            continue
        key = no_proxy_key(host)
        if key in seen:
            continue
        entries.append(host)
        seen.add(key)
    return entries


def ensure_local_no_proxy(params: dict[str, Any], config_path: Path | None = None) -> None:
    entries = no_proxy_entries()
    seen = {no_proxy_key(entry) for entry in entries}
    for entry in local_no_proxy_entries(params, config_path):
        key = no_proxy_key(entry)
        if key in seen:
            continue
        entries.append(entry)
        seen.add(key)
    value = ",".join(entries)
    os.environ["NO_PROXY"] = value
    os.environ["no_proxy"] = value


def config_setting(params: dict[str, Any], param_name: str, env_name: str, default: str) -> str:
    value = params.get(param_name)
    if value is None or str(value) == "":
        value = os.environ.get(env_name)
    if value is None or str(value) == "":
        value = default
    return str(value)


def config_int_setting(params: dict[str, Any], param_name: str, env_name: str, default: int) -> int:
    value = config_setting(params, param_name, env_name, str(default))
    try:
        return int(value)
    except ValueError as exc:
        raise RuntimeError(f"{env_name} must be an integer, got {value!r}") from exc


def quoted_config(value: str) -> str:
    return json.dumps(str(value), ensure_ascii=False)


def secret_config_setting(params: dict[str, Any], param_name: str, env_name: str, default: str) -> str:
    value = params.get(param_name)
    if value is not None and str(value) != "":
        return quoted_config(str(value))
    if os.environ.get(env_name):
        return f"!ENV {env_name}"
    return quoted_config(default)


def generate_kag_config(path: Path, params: dict[str, Any]) -> None:
    host = (params.get("host") or "http://127.0.0.1:8887").rstrip("/")
    project_id = str(params.get("project_id") or os.environ.get("KNOTE_KAG_PROJECT_ID") or "1")
    namespace = str(params.get("namespace") or os.environ.get("KNOTE_KAG_NAMESPACE") or "KnoteKB")
    language = str(params.get("language") or os.environ.get("KNOTE_KAG_LANGUAGE") or "en")
    checkpoint_path = json.dumps(str(runtime_dir(params) / "ckpt"))
    openie_llm_type = quoted_config(config_setting(params, "openie_llm_type", "KNOTE_OPENIE_LLM_TYPE", "openai"))
    openie_llm_base_url = quoted_config(
        config_setting(params, "openie_llm_base_url", "KNOTE_OPENIE_LLM_BASE_URL", "http://localhost:11434/v1")
    )
    openie_llm_api_key = secret_config_setting(params, "openie_llm_api_key", "KNOTE_OPENIE_LLM_API_KEY", "ollama")
    openie_llm_model = quoted_config(
        config_setting(params, "openie_llm_model", "KNOTE_OPENIE_LLM_MODEL", "qwen2.5-7b-instruct")
    )
    chat_llm_type = quoted_config(config_setting(params, "chat_llm_type", "KNOTE_CHAT_LLM_TYPE", "openai"))
    chat_llm_base_url = quoted_config(
        config_setting(params, "chat_llm_base_url", "KNOTE_CHAT_LLM_BASE_URL", "http://localhost:11434/v1")
    )
    chat_llm_api_key = secret_config_setting(params, "chat_llm_api_key", "KNOTE_CHAT_LLM_API_KEY", "ollama")
    chat_llm_model = quoted_config(
        config_setting(params, "chat_llm_model", "KNOTE_CHAT_LLM_MODEL", "qwen2.5-7b-instruct")
    )
    vector_type = quoted_config(config_setting(params, "vector_type", "KNOTE_VECTOR_TYPE", "openai"))
    vector_base_url = quoted_config(
        config_setting(params, "vector_base_url", "KNOTE_VECTOR_BASE_URL", "http://localhost:11434/v1")
    )
    vector_api_key = secret_config_setting(params, "vector_api_key", "KNOTE_VECTOR_API_KEY", "ollama")
    vector_model = quoted_config(config_setting(params, "vector_model", "KNOTE_VECTOR_MODEL", "bge-m3"))
    vector_dimensions = config_int_setting(params, "vector_dimensions", "KNOTE_VECTOR_DIMENSIONS", 1024)
    config = f"""# Generated by knote. Copy this file to .knote/kag_config.yaml to customize it.
openie_llm: &openie_llm
  type: {openie_llm_type}
  base_url: {openie_llm_base_url}
  api_key: {openie_llm_api_key}
  model: {openie_llm_model}
  enable_check: false

chat_llm: &chat_llm
  type: {chat_llm_type}
  base_url: {chat_llm_base_url}
  api_key: {chat_llm_api_key}
  model: {chat_llm_model}
  enable_check: false

vectorize_model: &vectorize_model
  type: {vector_type}
  base_url: {vector_base_url}
  api_key: {vector_api_key}
  model: {vector_model}
  vector_dimensions: {vector_dimensions}
  enable_check: false
vectorizer: *vectorize_model

log:
  level: INFO

project:
  biz_scene: default
  host_addr: {host}
  id: "{project_id}"
  language: {language}
  namespace: {namespace}
  checkpoint_path: {checkpoint_path}

kag_builder_pipeline:
  chain:
    type: unstructured_builder_chain
    extractor:
      type: schema_free_extractor
      llm: *openie_llm
      ner_prompt:
        type: default_ner
      std_prompt:
        type: default_std
      triple_prompt:
        type: default_triple
    reader:
      type: dict_reader
    post_processor:
      type: kag_post_processor
    splitter:
      type: length_splitter
      split_length: 100000
      window_length: 0
    vectorizer:
      type: batch_vectorizer
      vectorize_model: *vectorize_model
    writer:
      type: kg_writer
  num_threads_per_chain: 1
  num_chains: 1
  scanner:
    type: json_scanner

search_api: &search_api
  type: openspg_search_api

graph_api: &graph_api
  type: openspg_graph_api

kg_cs: &kg_cs
  type: kg_cs_open_spg
  priority: 0
  path_select:
    type: exact_one_hop_select
    graph_api: *graph_api
    search_api: *search_api
  entity_linking:
    type: entity_linking
    graph_api: *graph_api
    search_api: *search_api
    recognition_threshold: 0.9
    exclude_types:
      - Chunk
      - AtomicQuery
      - KnowledgeUnit
      - Summary
      - Outline
      - Doc

kg_fr: &kg_fr
  type: kg_fr_knowledge_unit
  top_k: 20
  graph_api: *graph_api
  search_api: *search_api
  vectorize_model: *vectorize_model
  path_select:
    type: fuzzy_one_hop_select
    llm_client: *openie_llm
    graph_api: *graph_api
    search_api: *search_api
  ppr_chunk_retriever_tool:
    type: ppr_chunk_retriever
    llm_client: *chat_llm
    graph_api: *graph_api
    search_api: *search_api
  entity_linking:
    type: entity_linking
    graph_api: *graph_api
    search_api: *search_api
    recognition_threshold: 0.8
    exclude_types:
      - Chunk
      - AtomicQuery
      - KnowledgeUnit
      - Summary
      - Outline
      - Doc

rc: &rc
  type: rc_open_spg
  vector_chunk_retriever:
    type: vector_chunk_retriever
    vectorize_model: *vectorize_model
    score_threshold: 0.65
    search_api: *search_api
  graph_api: *graph_api
  search_api: *search_api
  vectorize_model: *vectorize_model
  top_k: 20

kag_hybrid_executor: &kag_hybrid_executor_conf
  type: kag_hybrid_retrieval_executor
  retrievers:
    - *kg_cs
    - *kg_fr
    - *rc
  merger:
    type: kag_merger
  enable_summary: true

kag_output_executor: &kag_output_executor_conf
  type: kag_output_executor
  llm_module: *chat_llm

kag_deduce_executor: &kag_deduce_executor_conf
  type: kag_deduce_executor
  llm_module: *chat_llm

py_code_based_math_executor: &py_code_based_math_executor_conf
  type: py_code_based_math_executor
  llm: *chat_llm

kag_solver_pipeline:
  type: kag_static_pipeline
  planner:
    type: lf_kag_static_planner
    llm: *chat_llm
    plan_prompt:
      type: default_lf_static_planning
    rewrite_prompt:
      type: default_rewrite_sub_task_query
  executors:
    - *kag_hybrid_executor_conf
    - *py_code_based_math_executor_conf
    - *kag_deduce_executor_conf
    - *kag_output_executor_conf
  generator:
    type: llm_index_generator
    llm_client: *chat_llm
    generated_prompt:
      type: default_refer_generator_prompt
    enable_ref: true
"""
    atomic_write_text(path, config)


def fake_response(req: dict[str, Any]) -> None:
    req_id = req.get("id", "")
    method = req.get("method", "")
    params = req.get("params") or {}
    workspace = workspace_path(params)
    query = params.get("query") or ""
    if method == "kag.health":
        result(req_id, {"status": "ok", "mode": "fake", "version": "0.8.0"})
    elif method == "kag.build":
        out_dir = runtime_dir(params)
        corpus_path, records = prepare_corpus(workspace, out_dir, params)
        progress(req_id, "scanning sources", 1, 3)
        progress(req_id, "extracting graph", 2, 3)
        result(
            req_id,
            {
                "status": "ok",
                "mode": "fake",
                "corpus_path": str(corpus_path),
                "documents": len(records),
                "entities": len(records),
                "relations": 0,
                "claims": len(records),
            },
            "fake KAG build complete",
        )
    elif method in {"kag.query", "kag.explain"}:
        result(
            req_id,
            {
                "answer": f"Fake KAG answer for: {query}",
                "evidence": ["tests/fixtures/basic-kb/sources/intro.md"],
                "uncertainty": "fake adapter mode",
            },
        )
    elif method == "kag.cancel":
        result(req_id, {"status": "cancelled"})
    else:
        error(req_id, f"unknown method: {method}")


def check_real_health(req: dict[str, Any], host_override: str = "") -> tuple[dict[str, Any] | None, str | None]:
    params = req.get("params") or {}
    ensure_local_no_proxy(params)
    host = (host_override or params.get("host") or "http://127.0.0.1:8887").rstrip("/")
    try:
        import kag  # type: ignore

        kag_version = getattr(kag, "__version__", "")
        if not kag_version:
            try:
                from importlib.metadata import version

                kag_version = version("openspg-kag")
            except Exception:
                kag_version = "unknown"
    except Exception as exc:  # pragma: no cover - depends on local env
        return None, f"OpenSPG/KAG is not importable: {exc}"
    try:
        with urlrequest.urlopen(host, timeout=2) as response:  # nosec B310 - local configured host
            status = response.status
    except urlerror.HTTPError as exc:  # pragma: no cover - depends on local env
        status = exc.code
    except Exception as exc:  # pragma: no cover - depends on local env
        return None, f"OpenSPG host is unavailable at {host}: {exc}"
    return {"status": "ok", "mode": "real", "host": host, "http_status": status, "version": kag_version}, None


def real_health(req: dict[str, Any]) -> None:
    req_id = req.get("id", "")
    data, err = check_real_health(req)
    if err:
        error(req_id, err)
        return
    result(req_id, data or {})


def init_kag_config(config_path: Path) -> Any:
    from kag.common.conf import init_env, KAGConfigAccessor  # type: ignore

    init_env(config_file=str(config_path))
    return KAGConfigAccessor.get_config()


def run_kag_build(req: dict[str, Any]) -> dict[str, Any]:
    params = req.get("params") or {}
    workspace = workspace_path(params)
    out_dir = runtime_dir(params)
    corpus_path, records = prepare_corpus(workspace, out_dir, params)
    if not records:
        raise RuntimeError(f"no Markdown or text sources found under {workspace / 'sources'}")
    config_path = select_config(params, out_dir)
    ensure_local_no_proxy(params, config_path)
    init_kag_config(config_path)

    from kag.builder.runner import BuilderChainRunner  # type: ignore
    from kag.common.conf import KAG_CONFIG  # type: ignore
    from kag.common.registry import import_modules_from_path  # type: ignore

    import_modules_from_path(str(config_path.parent))
    pipeline = KAG_CONFIG.all_config.get("kag_builder_pipeline")
    if not pipeline:
        raise RuntimeError(f"kag_builder_pipeline missing in {config_path}")
    runner = BuilderChainRunner.from_config(pipeline)
    _, build_output = capture_stdout(runner.invoke, str(corpus_path))
    build_summary = parse_build_summary(build_output)
    ensure_successful_build_summary(build_summary)
    return {
        "status": "ok",
        "mode": "real",
        "config_path": str(config_path),
        "corpus_path": str(corpus_path),
        "documents": len(records),
        "build_summary": build_summary or {},
    }


def normalize_solver_output(value: Any) -> tuple[str, str]:
    trace = ""
    answer: Any = value
    if isinstance(value, tuple) and value:
        answer = value[0]
        if len(value) > 1:
            trace = normalize_trace(value[1])
    elif isinstance(value, dict):
        answer = value.get("answer") or value.get("result") or value
        trace = normalize_trace(value.get("trace") or value.get("traceLog") or value.get("report"))
    return str(answer), trace


def normalize_trace(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value[:4000]
    if hasattr(value, "to_dict"):
        try:
            return json.dumps(value.to_dict(), ensure_ascii=False, default=str)[:4000]
        except Exception:
            pass
    return json.dumps(value, ensure_ascii=False, default=str)[:4000]


def method_overridden(instance: Any, base_cls: Any, name: str) -> bool:
    return getattr(type(instance), name, None) is not getattr(base_cls, name, None)


def run_solver_pipeline(pipeline: Any, base_cls: Any, query: str) -> Any:
    if hasattr(pipeline, "run"):
        return pipeline.run(query)
    if method_overridden(pipeline, base_cls, "invoke"):
        try:
            return pipeline.invoke(query)
        except NotImplementedError:
            pass
    if method_overridden(pipeline, base_cls, "ainvoke"):
        import asyncio

        return asyncio.run(pipeline.ainvoke(query))
    raise RuntimeError("KAG solver pipeline has no concrete run/invoke/ainvoke method")


def run_kag_query(req: dict[str, Any], explain: bool = False) -> dict[str, Any]:
    params = req.get("params") or {}
    query = str(params.get("query") or "").strip()
    if not query:
        raise RuntimeError("query is required")
    out_dir = runtime_dir(params)
    config_path = select_config(params, out_dir, generate=False)
    ensure_local_no_proxy(params, config_path)
    init_kag_config(config_path)

    from kag.common.conf import KAG_CONFIG  # type: ignore
    from kag.common.registry import import_modules_from_path  # type: ignore
    from kag.interface import SolverPipelineABC  # type: ignore

    import_modules_from_path(str(config_path.parent))
    pipeline_conf = KAG_CONFIG.all_config.get("kag_solver_pipeline")
    if not pipeline_conf:
        raise RuntimeError(f"kag_solver_pipeline missing in {config_path}")
    pipeline = SolverPipelineABC.from_config(pipeline_conf)
    raw = run_solver_pipeline(pipeline, SolverPipelineABC, query)
    answer, trace = normalize_solver_output(raw)
    data = {
        "answer": answer,
        "evidence": [],
        "uncertainty": "",
        "mode": "real",
        "config_path": str(config_path),
    }
    if explain:
        data["explanation"] = trace or "KAG did not return a structured explanation trace."
    return data


def real_response(req: dict[str, Any]) -> None:
    req_id = req.get("id", "")
    method = req.get("method", "")
    if method == "kag.health":
        real_health(req)
        return
    if method == "kag.cancel":
        result(req_id, {"status": "cancelled"})
        return
    if method not in {"kag.build", "kag.query", "kag.explain"}:
        error(req_id, f"unknown method: {method}")
        return
    params = req.get("params") or {}
    try:
        config_path = select_config(params, runtime_dir(params), generate=method == "kag.build")
    except Exception as exc:
        error(req_id, str(exc))
        return
    ensure_local_no_proxy(params, config_path)
    health, health_error = check_real_health(req, config_host(config_path))
    if health_error:
        error(req_id, health_error)
        return
    try:
        if method == "kag.build":
            progress(req_id, "preparing corpus", 1, 4)
            progress(req_id, "initializing KAG config", 2, 4)
            progress(req_id, "running KAG builder", 3, 4)
            data = run_capturing_stdout(run_kag_build, req)
            data["health"] = health
            result(req_id, data, "KAG build complete")
            return
        if method == "kag.query":
            progress(req_id, "running KAG solver", 1, 1)
            result(req_id, run_capturing_stdout(run_kag_query, req), "KAG query complete")
            return
        if method == "kag.explain":
            progress(req_id, "running KAG solver with explanation", 1, 1)
            result(req_id, run_capturing_stdout(run_kag_query, req, explain=True), "KAG explain complete")
            return
    except Exception as exc:  # pragma: no cover - depends on local KAG/OpenSPG
        error(req_id, f"real OpenSPG/KAG execution failed: {exc}")
        return
    error(req_id, f"unknown method: {method}")


def main() -> int:
    fake = os.environ.get("KNOTE_KAG_FAKE") == "1"
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as exc:
            error("", f"invalid json: {exc}")
            continue
        try:
            if fake:
                fake_response(req)
            else:
                real_response(req)
        except Exception as exc:  # pragma: no cover - defensive boundary
            error(req.get("id", ""), str(exc))
        time.sleep(0.01)
        break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
