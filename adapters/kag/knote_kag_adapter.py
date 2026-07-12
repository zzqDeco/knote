#!/usr/bin/env python3
"""knote OpenSPG/KAG NDJSON adapter.

The adapter keeps KAG-specific behavior behind a stable knote protocol. It has
an explicit fake mode for deterministic local tests:

    KNOTE_KAG_FAKE=1 python3 adapters/kag/knote_kag_adapter.py
"""

from __future__ import annotations

import hashlib
import importlib
import json
import math
import os
import re
import sys
import time
from ipaddress import ip_address
from contextlib import contextmanager, redirect_stdout
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


def error(req_id: str, message: str, code: str = "") -> None:
    payload = {"id": req_id, "type": "error", "error": message}
    if code:
        payload["code"] = code
    emit(payload)


BUILD_SUMMARY_RE = re.compile(
    r"Done process\s+(?P<total>\d+)\s+records,\s+with\s+(?P<success>\d+)\s+successfully processed and\s+(?P<failures>\d+)\s+failures? encountered",
    re.IGNORECASE,
)
CONFIG_TEMPLATE_RE = re.compile(
    r"\{\{\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:\s*\|\s*default\(\s*(?P<default>[^)]*)\s*\))?\s*\}\}"
)
PRIMITIVE_METHODS = frozenset({"kag.retrieve", "kag.expand", "kag.generate"})
UNSUPPORTED_PRIMITIVE_CODE = "unsupported_primitive"
INVALID_REQUEST_CODE = "invalid_request"
TEST_STAGE_SPY_ENV = "KNOTE_KAG_TEST_STAGE_SPY"
TEST_DELAY_MS_ENV = "KNOTE_KAG_TEST_DELAY_MS"

CANDIDATE_FIELDS = frozenset({"resource", "score"})
RESOURCE_FIELDS = frozenset(
    {
        "resource_id",
        "type",
        "tenant_id",
        "knowledge_base_id",
        "authz_object",
        "authorization_resource_id",
        "content_digest",
        "versions",
        "serving_state",
    }
)
RESOURCE_VERSION_FIELDS = frozenset({"source", "content", "acl", "index", "graph", "projection"})
EVIDENCE_FIELDS = frozenset({"resource", "content", "citation_handle"})
RESOURCE_ID_RE = re.compile(r"res_[0-9a-f]{32}\Z")
CONTENT_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
RESOURCE_TYPES = frozenset({"document", "chunk", "entity", "claim", "derived_artifact"})

FAKE_INTRO_ID = "res_00000000000000000000000000000001"
FAKE_DENIED_CANARY_ID = "res_00000000000000000000000000000002"
FAKE_OVERVIEW_ID = "res_00000000000000000000000000000003"
FAKE_LOCAL_FIRST_ID = "res_00000000000000000000000000000004"
FAKE_DENIED_FRONTIER_ID = "res_00000000000000000000000000000005"
FAKE_DENIED_CANARY_DETAIL_ID = "res_00000000000000000000000000000006"
FAKE_DENIED_NEXT_HOP_ID = "res_00000000000000000000000000000007"
FAKE_RUNTIME_ID = "res_00000000000000000000000000000008"
FAKE_CONTENT_BY_ID = {
    FAKE_INTRO_ID: "knote is local-first.",
    FAKE_DENIED_CANARY_ID: "DENIED CANARY BODY must never cross the authorization boundary",
    FAKE_OVERVIEW_ID: "knote exposes a versioned knowledge workflow.",
    FAKE_LOCAL_FIRST_ID: "Its runtime can authorize graph stages before generation.",
    FAKE_DENIED_FRONTIER_ID: "DENIED FRONTIER BODY must never reach a later hop",
    FAKE_DENIED_CANARY_DETAIL_ID: "DENIED CANARY DETAIL must never reach graph output",
    FAKE_DENIED_NEXT_HOP_ID: "DENIED NEXT HOP BODY must never be expanded",
    FAKE_RUNTIME_ID: "The runtime delegates graph storage to KAG.",
}


def fake_resource(resource_id: str, resource_type: str) -> dict[str, Any]:
    return {
        "resource_id": resource_id,
        "type": resource_type,
        "tenant_id": "tenant_fake",
        "knowledge_base_id": "kb_fake",
        "authz_object": f"{resource_type}:{resource_id}",
        "authorization_resource_id": resource_id,
        "content_digest": "sha256:"
        + hashlib.sha256(FAKE_CONTENT_BY_ID[resource_id].encode("utf-8")).hexdigest(),
        "versions": {
            "source": "source_fake_v1",
            "content": "content_fake_v1",
            "acl": "acl_fake_v1",
            "index": "index_fake_v1",
            "graph": "graph_fake_v1",
            "projection": "projection_fake_v1",
        },
        "serving_state": "serving",
    }


FAKE_CANDIDATES = (
    {"resource": fake_resource(FAKE_INTRO_ID, "document"), "score": 0.99},
    {"resource": fake_resource(FAKE_DENIED_CANARY_ID, "document"), "score": 0.98},
    {"resource": fake_resource(FAKE_OVERVIEW_ID, "document"), "score": 0.90},
    {"resource": fake_resource(FAKE_LOCAL_FIRST_ID, "claim"), "score": 0.96},
    {"resource": fake_resource(FAKE_DENIED_FRONTIER_ID, "claim"), "score": 0.95},
    {"resource": fake_resource(FAKE_DENIED_CANARY_DETAIL_ID, "claim"), "score": 0.94},
    {"resource": fake_resource(FAKE_DENIED_NEXT_HOP_ID, "document"), "score": 0.93},
    {"resource": fake_resource(FAKE_RUNTIME_ID, "document"), "score": 0.91},
)
FAKE_CANDIDATES_BY_ID = {
    candidate["resource"]["resource_id"]: candidate for candidate in FAKE_CANDIDATES
}
FAKE_RETRIEVE_IDS = (FAKE_INTRO_ID, FAKE_DENIED_CANARY_ID, FAKE_OVERVIEW_ID)
FAKE_EXPANSIONS = {
    FAKE_INTRO_ID: (
        (FAKE_LOCAL_FIRST_ID, 1),
        (FAKE_DENIED_FRONTIER_ID, 1),
    ),
    FAKE_DENIED_CANARY_ID: ((FAKE_DENIED_CANARY_DETAIL_ID, 1),),
    FAKE_LOCAL_FIRST_ID: ((FAKE_RUNTIME_ID, 2),),
    FAKE_DENIED_FRONTIER_ID: ((FAKE_DENIED_NEXT_HOP_ID, 2),),
}


class AdapterRequestError(RuntimeError):
    def __init__(self, message: str, code: str = INVALID_REQUEST_CODE) -> None:
        super().__init__(message)
        self.code = code


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


def configured_source_path(params: dict[str, Any]) -> Path | None:
    workspace = workspace_path(params)
    explicit = params.get("config_path")
    if explicit:
        path = Path(explicit)
        candidate = path if path.is_absolute() else workspace / path
        if candidate.exists():
            return candidate.resolve()
        return None
    for candidate in (workspace / ".knote" / "kag_config.yaml", workspace / "kag_config.yaml"):
        if candidate.exists():
            return candidate.resolve()
    return None


def config_resource_dir(params: dict[str, Any], config_path: Path) -> Path:
    source = configured_source_path(params)
    return source.parent if source is not None else config_path.parent


@contextmanager
def working_directory(path: Path) -> Any:
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def build_idempotency_key(params: dict[str, Any]) -> str:
    value = params.get("idempotency_key")
    if value is None:
        return ""
    if not isinstance(value, str) or not value.strip():
        raise AdapterRequestError("idempotency_key must be a non-empty string")
    if value != value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise AdapterRequestError("idempotency_key contains invalid whitespace or control characters")
    return value


def build_checkpoint_path(out_dir: Path, params: dict[str, Any]) -> Path:
    key = build_idempotency_key(params)
    if not key:
        return out_dir / "ckpt"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return out_dir / "ckpt" / "runs" / digest


def build_receipt_path(out_dir: Path, idempotency_key: str) -> Path:
    digest = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
    return out_dir / "idempotency" / f"{digest}.json"


def load_build_receipt(out_dir: Path, idempotency_key: str) -> dict[str, Any] | None:
    if not idempotency_key:
        return None
    path = build_receipt_path(out_dir, idempotency_key)
    if not path.exists():
        return None
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid KAG build idempotency receipt: {path}: {exc}") from exc
    if not isinstance(receipt, dict) or receipt.get("version") != 1:
        raise RuntimeError(f"invalid KAG build idempotency receipt: {path}")
    if receipt.get("idempotency_key") != idempotency_key or not isinstance(receipt.get("data"), dict):
        raise RuntimeError(f"KAG build idempotency receipt does not match request: {path}")
    return dict(receipt["data"])


def store_build_receipt(out_dir: Path, idempotency_key: str, data: dict[str, Any]) -> None:
    if not idempotency_key:
        return
    receipt = {"version": 1, "idempotency_key": idempotency_key, "data": data}
    atomic_write_text(
        build_receipt_path(out_dir, idempotency_key),
        json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
    )


def select_config(params: dict[str, Any], out_dir: Path, *, generate: bool = True) -> Path:
    workspace = workspace_path(params)
    explicit = params.get("config_path")
    if explicit:
        path = Path(explicit)
        candidate = path if path.is_absolute() else workspace / path
        if not candidate.exists():
            raise FileNotFoundError(f"explicit KAG config not found: {candidate}")
        return select_projection_config(candidate.resolve(), out_dir, params, generate=generate)
    candidates = [workspace / ".knote" / "kag_config.yaml", workspace / "kag_config.yaml"]
    for candidate in candidates:
        if candidate.exists():
            return select_projection_config(candidate.resolve(), out_dir, params, generate=generate)
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


def select_projection_config(base: Path, out_dir: Path, params: dict[str, Any], *, generate: bool) -> Path:
    namespace = str(params.get("namespace") or "").strip()
    if not projection_isolation_requested(params, out_dir, namespace):
        return base
    target = out_dir / "kag_config.yaml"
    if target.exists():
        if generate and build_idempotency_key(params):
            return projection_config(base, out_dir, params)
        return target.resolve()
    if not generate:
        raise FileNotFoundError(f"projection KAG config not found; run /build first: {target}")
    return projection_config(base, out_dir, params)


def projection_isolation_requested(params: dict[str, Any], out_dir: Path, namespace: str) -> bool:
    marker = params.get("projection_isolated")
    if marker is not None:
        return marker is True and bool(namespace)
    return bool(namespace) and out_dir.name == namespace and out_dir.parent.name == "projections"


def fallback_project_line(lines: list[str], base: Path) -> int:
    project_lines = [
        index
        for index, line in enumerate(lines)
        if not line.startswith((" ", "\t"))
        and re.match(r"^(?:project|'project'|\"project\")\s*:", line)
    ]
    if not project_lines:
        raise RuntimeError(f"KAG config has no top-level project section: {base}")
    if len(project_lines) != 1:
        raise RuntimeError(f"KAG config has duplicate top-level project sections: {base}")
    index = project_lines[0]
    line = lines[index]
    remainder = line[line.index(":") + 1 :].strip()
    if remainder.startswith("&"):
        parts = remainder.split(maxsplit=1)
        remainder = parts[1].strip() if len(parts) == 2 else ""
    if remainder.startswith("{"):
        if flow_mapping_end(remainder) is None:
            raise RuntimeError(f"invalid KAG config YAML project mapping: {base}")
        return index
    if remainder and not remainder.startswith("#"):
        raise RuntimeError(f"KAG config project section must be a mapping: {base}")
    for child in lines[index + 1 :]:
        if not child.strip() or child.lstrip().startswith("#"):
            continue
        if not child.startswith((" ", "\t")) or child.lstrip().startswith("-"):
            break
        if ":" in child:
            return index
        break
    raise RuntimeError(f"KAG config project section must be a mapping: {base}")


def structured_project_line(text: str, lines: list[str], base: Path) -> int:
    try:
        yaml = importlib.import_module("yaml")
    except ModuleNotFoundError:
        return fallback_project_line(lines, base)
    # Compose nodes without constructing KAG-specific tags such as !ENV.
    try:
        root = yaml.compose(text)
    except yaml.YAMLError as exc:
        raise RuntimeError(f"invalid KAG config YAML: {base}: {exc}") from exc
    if not isinstance(root, yaml.MappingNode):
        raise RuntimeError(f"KAG config must be a top-level mapping: {base}")
    projects = [
        (key, value)
        for key, value in root.value
        if isinstance(key, yaml.ScalarNode) and key.value == "project"
    ]
    if not projects:
        raise RuntimeError(f"KAG config has no top-level project section: {base}")
    if len(projects) != 1:
        raise RuntimeError(f"KAG config has duplicate top-level project sections: {base}")
    key, project = projects[0]
    if not isinstance(project, yaml.MappingNode):
        raise RuntimeError(f"KAG config project section must be a mapping: {base}")
    return key.start_mark.line


def flow_mapping_end(value: str) -> int | None:
    depth = 0
    quote = ""
    escaped = False
    for index, char in enumerate(value):
        if quote:
            if quote == '"' and char == "\\" and not escaped:
                escaped = True
                continue
            if char == quote and not escaped:
                quote = ""
            escaped = False
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                trailing = value[index + 1 :].strip()
                return index if not trailing or trailing.startswith("#") else None
            if depth < 0:
                return None
    return None


def split_flow_mapping_entries(value: str) -> list[str]:
    entries: list[str] = []
    start = 0
    depth = 0
    quote = ""
    escaped = False
    for index, char in enumerate(value):
        if quote:
            if quote == '"' and char == "\\" and not escaped:
                escaped = True
                continue
            if char == quote and not escaped:
                quote = ""
            escaped = False
            continue
        if char in {"'", '"'}:
            quote = char
        elif char in "[{":
            depth += 1
        elif char in "]}":
            depth -= 1
        elif char == "," and depth == 0:
            entries.append(value[start:index].strip())
            start = index + 1
    tail = value[start:].strip()
    if tail:
        entries.append(tail)
    return entries


def rewrite_flow_project(
    lines: list[str], project_index: int, namespace: str, checkpoint_path: Path
) -> bool:
    line = lines[project_index]
    colon = line.index(":")
    remainder = line[colon + 1 :].strip()
    anchor = ""
    if remainder.startswith("&"):
        parts = remainder.split(maxsplit=1)
        anchor = parts[0]
        remainder = parts[1].strip() if len(parts) == 2 else ""
    if not remainder.startswith("{"):
        return False
    end = flow_mapping_end(remainder)
    if end is None:
        return False
    entries = [
        entry
        for entry in split_flow_mapping_entries(remainder[1:end])
        if not re.match(
            r"^(?:namespace|checkpoint_path|'namespace'|'checkpoint_path'|\"namespace\"|\"checkpoint_path\")\s*:",
            entry,
        )
    ]
    entries.extend(
        [
            f"namespace: {quoted_config(namespace)}",
            f"checkpoint_path: {quoted_config(str(checkpoint_path))}",
        ]
    )
    mapping = "{" + ", ".join(entries) + "}"
    comment = remainder[end + 1 :].strip()
    project_line = line[: colon + 1]
    if anchor:
        project_line += f" {anchor}"
    project_line += f" {mapping}"
    if comment:
        project_line += f" {comment}"
    lines[project_index] = project_line
    return True


def projection_config(base: Path, out_dir: Path, params: dict[str, Any]) -> Path:
    namespace = str(params.get("namespace") or "").strip()
    if not namespace:
        return base
    target = out_dir / "kag_config.yaml"
    if base.resolve() == target.resolve():
        return base
    text = base.read_text(encoding="utf-8")
    lines = text.splitlines()
    project_index = structured_project_line(text, lines, base)
    checkpoint_path = build_checkpoint_path(out_dir, params)
    if rewrite_flow_project(lines, project_index, namespace, checkpoint_path):
        ensure_runtime_excluded(workspace_path(params), out_dir)
        atomic_write_text(target, "\n".join(lines) + "\n")
        return target.resolve()
    project_end = len(lines)
    namespace_written = False
    checkpoint_written = False
    project_indent: int | None = None
    for index, line in enumerate(lines[project_index + 1 :], start=project_index + 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 0:
            project_end = index
            break
        if project_indent is None or indent < project_indent:
            project_indent = indent
    if project_indent is None:
        project_indent = 2
    for index in range(project_index + 1, project_end):
        line = lines[index]
        indent = len(line) - len(line.lstrip())
        if indent != project_indent:
            continue
        stripped = line.strip()
        if re.match(r"^namespace\s*:", stripped):
            lines[index] = " " * project_indent + f"namespace: {quoted_config(namespace)}"
            namespace_written = True
        elif re.match(r"^checkpoint_path\s*:", stripped):
            lines[index] = (
                " " * project_indent + f"checkpoint_path: {quoted_config(str(checkpoint_path))}"
            )
            checkpoint_written = True
    additions: list[str] = []
    if not namespace_written:
        additions.append(" " * project_indent + f"namespace: {quoted_config(namespace)}")
    if not checkpoint_written:
        additions.append(
            " " * project_indent + f"checkpoint_path: {quoted_config(str(checkpoint_path))}"
        )
    if additions:
        lines[project_end:project_end] = additions
    ensure_runtime_excluded(workspace_path(params), out_dir)
    atomic_write_text(target, "\n".join(lines) + "\n")
    return target.resolve()


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
    checkpoint_path = json.dumps(str(build_checkpoint_path(runtime_dir(params), params)))
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


def primitive_params(req: dict[str, Any]) -> dict[str, Any]:
    params = req.get("params")
    if params is None:
        return {}
    if not isinstance(params, dict):
        raise AdapterRequestError("params must be an object")
    return params


def required_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AdapterRequestError(f"{field} must be a non-empty string")
    return value.strip()


def required_content(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AdapterRequestError(f"{field} must be a non-empty string")
    return value


def primitive_limit(params: dict[str, Any], default: int) -> int:
    value = params.get("limit", default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise AdapterRequestError("limit must be an integer")
    if value < 1 or value > 100:
        raise AdapterRequestError("limit must be between 1 and 100")
    return value


def validate_exact_fields(value: dict[str, Any], expected: frozenset[str], field: str) -> None:
    actual = set(value)
    if actual == expected:
        return
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    details: list[str] = []
    if missing:
        details.append("missing " + ", ".join(missing))
    if unexpected:
        details.append("unexpected " + ", ".join(unexpected))
    raise AdapterRequestError(f"{field} has invalid fields ({'; '.join(details)})")


def validate_resource(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AdapterRequestError(f"{field} must be an object")
    validate_exact_fields(value, RESOURCE_FIELDS, field)
    resource_id = required_string(value.get("resource_id"), f"{field}.resource_id")
    if not RESOURCE_ID_RE.fullmatch(resource_id):
        raise AdapterRequestError(f"{field}.resource_id must be an opaque res_ identifier")
    resource_type = required_string(value.get("type"), f"{field}.type")
    if resource_type not in RESOURCE_TYPES:
        raise AdapterRequestError(f"{field}.type is unsupported")
    tenant_id = required_string(value.get("tenant_id"), f"{field}.tenant_id")
    knowledge_base_id = required_string(value.get("knowledge_base_id"), f"{field}.knowledge_base_id")
    authz_object = required_string(value.get("authz_object"), f"{field}.authz_object")
    authorization_resource_id = required_string(
        value.get("authorization_resource_id"), f"{field}.authorization_resource_id"
    )
    if not RESOURCE_ID_RE.fullmatch(authorization_resource_id):
        raise AdapterRequestError(
            f"{field}.authorization_resource_id must be an opaque res_ identifier"
        )
    if resource_type != "chunk" and authorization_resource_id != resource_id:
        raise AdapterRequestError(
            f"{field}.authorization_resource_id must match non-chunk resource_id"
        )
    content_digest = required_string(value.get("content_digest"), f"{field}.content_digest")
    if not CONTENT_DIGEST_RE.fullmatch(content_digest):
        raise AdapterRequestError(f"{field}.content_digest must be a sha256 digest")
    versions = value.get("versions")
    if not isinstance(versions, dict):
        raise AdapterRequestError(f"{field}.versions must be an object")
    validate_exact_fields(versions, RESOURCE_VERSION_FIELDS, f"{field}.versions")
    normalized_versions = {
        name: required_string(versions.get(name), f"{field}.versions.{name}")
        for name in sorted(RESOURCE_VERSION_FIELDS)
    }
    serving_state = required_string(value.get("serving_state"), f"{field}.serving_state")
    if serving_state != "serving":
        raise AdapterRequestError(f"{field}.serving_state must be serving")
    return {
        "resource_id": resource_id,
        "type": resource_type,
        "tenant_id": tenant_id,
        "knowledge_base_id": knowledge_base_id,
        "authz_object": authz_object,
        "authorization_resource_id": authorization_resource_id,
        "content_digest": content_digest,
        "versions": normalized_versions,
        "serving_state": serving_state,
    }


def validate_candidate(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AdapterRequestError(f"{field} must be an object")
    validate_exact_fields(value, CANDIDATE_FIELDS, field)
    resource = validate_resource(value.get("resource"), f"{field}.resource")
    score = value.get("score")
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        raise AdapterRequestError(f"{field}.score must be a number")
    if not math.isfinite(score):
        raise AdapterRequestError(f"{field}.score must be finite")
    if score < 0 or score > 1:
        raise AdapterRequestError(f"{field}.score must be between 0 and 1")
    return {"resource": resource, "score": float(score)}


def validate_evidence(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AdapterRequestError(f"{field} must be an object")
    validate_exact_fields(value, EVIDENCE_FIELDS, field)
    resource = validate_resource(value.get("resource"), f"{field}.resource")
    content = required_content(value.get("content"), f"{field}.content")
    content_digest = "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest()
    if content_digest != resource["content_digest"]:
        raise AdapterRequestError(f"{field}.content does not match resource.content_digest")
    return {
        "resource": resource,
        "content": content,
        "citation_handle": required_string(value.get("citation_handle"), f"{field}.citation_handle"),
    }


def copy_fake_candidate(resource_id: str) -> dict[str, Any]:
    candidate = FAKE_CANDIDATES_BY_ID[resource_id]
    resource = candidate["resource"]
    return {
        "resource": {**resource, "versions": dict(resource["versions"])},
        "score": candidate["score"],
    }


def require_fake_resource_binding(resource: dict[str, Any], field: str) -> None:
    resource_id = resource["resource_id"]
    candidate = FAKE_CANDIDATES_BY_ID.get(resource_id)
    if candidate is None:
        raise AdapterRequestError(f"{field}.resource_id is not present in the fake serving projection")
    if resource != candidate["resource"]:
        raise AdapterRequestError(f"{field} does not match the exact fake serving resource handle")


def maybe_test_primitive_delay() -> None:
    value = os.environ.get(TEST_DELAY_MS_ENV, "")
    if not value:
        return
    try:
        delay_ms = int(value)
    except ValueError as exc:
        raise AdapterRequestError(f"{TEST_DELAY_MS_ENV} must be an integer") from exc
    if delay_ms < 0 or delay_ms > 5000:
        raise AdapterRequestError(f"{TEST_DELAY_MS_ENV} must be between 0 and 5000")
    time.sleep(delay_ms / 1000)


def add_test_stage_spy(
    data: dict[str, Any], stages: list[tuple[str, list[str]]]
) -> dict[str, Any]:
    if os.environ.get(TEST_STAGE_SPY_ENV) != "1":
        return data
    data["debug"] = {
        "stages": [
            {"stage": stage, "resource_ids": list(resource_ids), "count": len(resource_ids)}
            for stage, resource_ids in stages
        ]
    }
    return data


def fake_retrieve(params: dict[str, Any]) -> dict[str, Any]:
    required_string(params.get("query"), "query")
    limit = primitive_limit(params, len(FAKE_RETRIEVE_IDS))
    maybe_test_primitive_delay()
    retrieved = [
        (copy_fake_candidate(resource_id), FAKE_CONTENT_BY_ID[resource_id])
        for resource_id in FAKE_RETRIEVE_IDS[:limit]
    ]
    candidates = [candidate for candidate, _protected_content in retrieved]
    resource_ids = [candidate["resource"]["resource_id"] for candidate in candidates]
    return add_test_stage_spy(
        {"mode": "fake", "candidates": candidates},
        [("retrieve.output", resource_ids)],
    )


def fake_expand(params: dict[str, Any]) -> dict[str, Any]:
    frontier = params.get("frontier")
    if not isinstance(frontier, list) or not frontier:
        raise AdapterRequestError("frontier must be a list of candidate handles")
    handles = [validate_candidate(value, f"frontier[{index}]") for index, value in enumerate(frontier)]
    for index, handle in enumerate(handles):
        require_fake_resource_binding(handle["resource"], f"frontier[{index}].resource")
    frontier_ids = sorted(handle["resource"]["resource_id"] for handle in handles)
    if len(frontier_ids) != len(set(frontier_ids)):
        raise AdapterRequestError("frontier contains duplicate resource_id values")
    limit = primitive_limit(params, 10)
    maybe_test_primitive_delay()

    edges: list[dict[str, Any]] = []
    candidate_ids: set[str] = set()
    for from_resource_id in frontier_ids:
        for to_resource_id, hop in FAKE_EXPANSIONS.get(from_resource_id, ()):
            candidate_ids.add(to_resource_id)
            edges.append(
                {
                    "from_resource_id": from_resource_id,
                    "to_resource_id": to_resource_id,
                    "hop": hop,
                }
            )
    candidates = sorted(
        (copy_fake_candidate(resource_id) for resource_id in candidate_ids),
        key=lambda candidate: (-candidate["score"], candidate["resource"]["resource_id"]),
    )[:limit]
    output_ids = [candidate["resource"]["resource_id"] for candidate in candidates]
    included = set(output_ids)
    expansions = sorted(
        (edge for edge in edges if edge["to_resource_id"] in included),
        key=lambda edge: (edge["hop"], edge["from_resource_id"], edge["to_resource_id"]),
    )
    return add_test_stage_spy(
        {"mode": "fake", "candidates": candidates, "expansions": expansions},
        [
            ("expand.frontier_input", frontier_ids),
            ("expand.candidate_output", output_ids),
        ],
    )


def fake_generate(params: dict[str, Any]) -> dict[str, Any]:
    question = required_string(params.get("question"), "question")
    evidence = params.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise AdapterRequestError("evidence must be a non-empty list of already-authorized evidence objects")
    items = [validate_evidence(value, f"evidence[{index}]") for index, value in enumerate(evidence)]
    for index, item in enumerate(items):
        require_fake_resource_binding(item["resource"], f"evidence[{index}].resource")
    resource_ids = [item["resource"]["resource_id"] for item in items]
    citation_handles = [item["citation_handle"] for item in items]
    if len(resource_ids) != len(set(resource_ids)):
        raise AdapterRequestError("evidence contains duplicate resource_id values")
    if len(citation_handles) != len(set(citation_handles)):
        raise AdapterRequestError("evidence contains duplicate citation_handle values")
    maybe_test_primitive_delay()

    answer = f"Fake generated answer for: {question} Supported by: " + " ".join(
        item["content"] for item in items
    )
    citations = [
        {"handle": item["citation_handle"], "resource_id": item["resource"]["resource_id"]}
        for item in items
    ]
    return add_test_stage_spy(
        {
            "mode": "fake",
            "answer": answer,
            "citations": citations,
            "evidence_resource_ids": resource_ids,
            "trace": {"resource_ids": resource_ids, "count": len(resource_ids)},
        },
        [
            ("generate.evidence_input", resource_ids),
            ("generate.citation_output", resource_ids),
        ],
    )


def fake_response(req: dict[str, Any]) -> None:
    req_id = req.get("id", "")
    method = req.get("method", "")
    if method in PRIMITIVE_METHODS:
        params = primitive_params(req)
        handlers = {
            "kag.retrieve": fake_retrieve,
            "kag.expand": fake_expand,
            "kag.generate": fake_generate,
        }
        result(req_id, handlers[method](params))
        return
    params = req.get("params") or {}
    query = params.get("query") or ""
    if method == "kag.health":
        result(req_id, {"status": "ok", "mode": "fake", "version": "0.8.0"})
    elif method == "kag.build":
        workspace = workspace_path(params)
        out_dir = runtime_dir(params)
        idempotency_key = build_idempotency_key(params)
        replay = load_build_receipt(out_dir, idempotency_key)
        if replay is not None:
            result(req_id, replay, "fake KAG build complete")
            return
        corpus_path, records = prepare_corpus(workspace, out_dir, params)
        progress(req_id, "scanning sources", 1, 3)
        progress(req_id, "extracting graph", 2, 3)
        data = {
            "status": "ok",
            "mode": "fake",
            "corpus_path": str(corpus_path),
            "documents": len(records),
            "entities": len(records),
            "relations": 0,
            "claims": len(records),
        }
        if idempotency_key:
            data["idempotency_key"] = idempotency_key
        store_build_receipt(out_dir, idempotency_key, data)
        result(
            req_id,
            data,
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
    idempotency_key = build_idempotency_key(params)
    replay = load_build_receipt(out_dir, idempotency_key)
    if replay is not None:
        return replay
    corpus_path, records = prepare_corpus(workspace, out_dir, params)
    if not records:
        raise RuntimeError(f"no Markdown or text sources found under {workspace / 'sources'}")
    config_path = select_config(params, out_dir)
    ensure_local_no_proxy(params, config_path)
    resource_dir = config_resource_dir(params, config_path)
    with working_directory(resource_dir):
        init_kag_config(config_path)

        from kag.builder.runner import BuilderChainRunner  # type: ignore
        from kag.common.conf import KAG_CONFIG  # type: ignore
        from kag.common.registry import import_modules_from_path  # type: ignore

        import_modules_from_path(str(resource_dir))
        pipeline = KAG_CONFIG.all_config.get("kag_builder_pipeline")
        if not pipeline:
            raise RuntimeError(f"kag_builder_pipeline missing in {config_path}")
        runner = BuilderChainRunner.from_config(pipeline)
        _, build_output = capture_stdout(runner.invoke, str(corpus_path))
    build_summary = parse_build_summary(build_output)
    ensure_successful_build_summary(build_summary)
    data = {
        "status": "ok",
        "mode": "real",
        "config_path": str(config_path),
        "corpus_path": str(corpus_path),
        "documents": len(records),
        "build_summary": build_summary or {},
    }
    if idempotency_key:
        data["idempotency_key"] = idempotency_key
    store_build_receipt(out_dir, idempotency_key, data)
    return data


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
    resource_dir = config_resource_dir(params, config_path)
    with working_directory(resource_dir):
        init_kag_config(config_path)

        from kag.common.conf import KAG_CONFIG  # type: ignore
        from kag.common.registry import import_modules_from_path  # type: ignore
        from kag.interface import SolverPipelineABC  # type: ignore

        import_modules_from_path(str(resource_dir))
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
    if method in PRIMITIVE_METHODS:
        error(
            req_id,
            f"{method} is not supported by the real OpenSPG/KAG adapter",
            UNSUPPORTED_PRIMITIVE_CODE,
        )
        return
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
    if method == "kag.build":
        try:
            idempotency_key = build_idempotency_key(params)
            replay = load_build_receipt(runtime_dir(params), idempotency_key)
        except Exception as exc:
            error(req_id, str(exc))
            return
        if replay is not None:
            result(req_id, replay, "KAG build complete")
            return
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
        if not isinstance(req, dict):
            error("", "request must be a JSON object", INVALID_REQUEST_CODE)
            continue
        req_id = req.get("id", "")
        try:
            if fake:
                fake_response(req)
            else:
                real_response(req)
        except AdapterRequestError as exc:
            error(req_id, str(exc), exc.code)
        except Exception as exc:  # pragma: no cover - defensive boundary
            error(req_id, str(exc))
        time.sleep(0.01)
        break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
