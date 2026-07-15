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
import select
import signal
import subprocess
import sys
import tempfile
import time
from copy import deepcopy
from functools import cmp_to_key
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
PRIMITIVE_METHODS = frozenset(
    {"kag.discover", "kag.retrieve", "kag.expand", "kag.generate"}
)
UNSUPPORTED_PRIMITIVE_CODE = "unsupported_primitive"
INVALID_REQUEST_CODE = "invalid_request"
INVALID_GRAPH_BINDING_CODE = "invalid_graph_binding"
PRIMITIVE_UNAVAILABLE_CODE = "primitive_unavailable"
INVALID_PRIMITIVE_RESPONSE_CODE = "invalid_primitive_response"
PERMISSIONED_PROVIDER_ENV = "KNOTE_KAG_PERMISSIONED_PROVIDER"
PERMISSIONED_PROVIDER_RUNNER_ARG = "--permissioned-provider-runner"
PERMISSIONED_PROVIDER_GUARDIAN_ARG = "--permissioned-provider-guardian"
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
GENERATE_PATH_FIELDS = frozenset({"resources", "claim_bindings"})
GENERATE_PATH_CLAIM_BINDING_FIELDS = frozenset(
    {
        "parent_resource_id",
        "claim_resource_id",
        "object_resource_id",
        "predicate_key",
    }
)
AUTHORIZATION_REQUIRED_FIELDS = frozenset(
    {
        "version",
        "tenant_id",
        "knowledge_base_id",
        "principal_id",
        "session_id",
        "request_id",
        "authorization_model_id",
        "identity_watermark",
        "acl_watermark",
        "consistency",
    }
)
AUTHORIZATION_OPTIONAL_FIELDS = frozenset({"agent_id", "task_id"})
AUTHORIZATION_CONSISTENCY_VALUES = frozenset(
    {"minimize_latency", "higher_consistency"}
)
AUTHORIZATION_CONTEXT_VERSION = "v1"
RESOURCE_ID_RE = re.compile(r"res_[0-9a-f]{32}\Z")
CONTENT_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
RESOURCE_TYPES = frozenset({"document", "chunk", "entity", "claim", "derived_artifact"})
GRAPH_BINDING_CONTRACT_VERSION_V1 = 1
GRAPH_BINDING_CONTRACT_VERSION = 2
SUPPORTED_GRAPH_BINDING_CONTRACT_VERSIONS = frozenset(
    {GRAPH_BINDING_CONTRACT_VERSION_V1, GRAPH_BINDING_CONTRACT_VERSION}
)
GRAPH_BINDINGS_ARTIFACT = "graph_bindings.jsonl"
CLAIM_BINDINGS_ARTIFACT = "claim_bindings.jsonl"
GRAPH_BINDING_FIELDS = frozenset({"version", "graph_object_id", "resource"})
CLAIM_SUPPORT_FIELDS = frozenset(
    {"support_key", "provenance", "provenance_resource_ids"}
)
CLAIM_BINDING_FIELDS = frozenset(
    {
        "version",
        "claim",
        "subject",
        "predicate_key",
        "object",
        "source_document",
        "derivation",
        "provenance",
        "subject_resource_id",
        "object_resource_id",
        "source_document_resource_id",
        "source_version",
        "provenance_resource_ids",
        "supports",
    }
)
CLAIM_BINDING_V1_FIELDS = frozenset(
    {
        "version",
        "claim",
        "subject",
        "predicate_key",
        "object",
        "source_document",
        "derivation",
        "provenance",
    }
)
CURRENT_POINTER_FIELDS = frozenset(
    {"version", "projection_id", "projection_version", "manifest_sha256"}
)
BUNDLE_MANIFEST_FIELDS = frozenset(
    {
        "version",
        "projection_id",
        "projection_version",
        "namespace",
        "authz_object",
        "authz_version",
        "graph_binding_contract_version",
        "source_snapshot",
        "generated_at",
        "files",
        "v1_compatibility",
    }
)
SOURCE_SNAPSHOT_FIELDS = frozenset({"version", "digest", "document_count"})
ARTIFACT_DESCRIPTOR_FIELDS = frozenset({"path", "sha256", "count", "size_bytes"})
GRAPH_OBJECT_ID_RE = re.compile(r"kg_[0-9a-f]{32}\Z")
CLAIM_PREDICATE_KEY_RE = re.compile(r"pred_[0-9a-f]{32}\Z")
CLAIM_SUPPORT_KEY_RE = re.compile(r"sup_[0-9a-f]{32}\Z")
SUPPORTED_CLAIM_PREDICATE_KEYS = frozenset(
    {
        "pred_117dbb19db72ab17c98e4ef1274d5981",
        "pred_2f262980c75e6161b9b4e515b2de1e39",
        "pred_5b962d789a179c3b0fef884c6ce16d3c",
        "pred_66312e5e57ebd0b4fff4ef544c5a4abd",
        "pred_6671808c414ad4b875384b8fa3bfc59c",
        "pred_70a81d065c4e01846e6f7ab070e14be4",
        "pred_8f3dc3703e8d493b1c38906cd34a06cc",
        "pred_a3b0b7f1948c58d586d3af99fee4704e",
        "pred_c2a0b72a30d819c4cd2a9024a1a2cbf9",
        "pred_f394e7077977ae111ead3df2693e7b22",
    }
)
PROJECTION_ID_RE = re.compile(r"prj_[0-9a-f]{32}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
PROVIDER_SPEC_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*\Z"
)
MAX_GRAPH_BINDING_FILE_BYTES = 64 << 20
MAX_GRAPH_BINDING_LINE_BYTES = 1 << 20
MAX_ARTIFACT_CURRENT_POINTER_BYTES = 64 << 10
MAX_ARTIFACT_BUNDLE_MANIFEST_BYTES = 4 << 20
MAX_PRIMITIVE_TEXT_BYTES = 1 << 20
MAX_PROVIDER_RESPONSE_BYTES = 2 << 20
PROVIDER_RUNNER_TIMEOUT_SECONDS = 30
MAX_PRIMITIVE_ITEMS = 100

PRIMITIVE_TRANSPORT_FIELDS = frozenset(
    {
        "workspace",
        "host",
        "config_path",
        "project_id",
        "namespace",
        "language",
        "runtime_dir",
    }
)
GRAPH_OPERATION_FIELDS = frozenset({"version", "template", "parameters"})
TRAVERSAL_PLAN_REQUIRED_FIELDS = frozenset(
    {
        "version",
        "predicate_allowlist_version",
        "resource_kind_allowlist_version",
        "projection_version",
        "identity_version",
        "start_resource_ids",
        "predicate_keys",
        "resource_kinds",
        "direction",
        "fields",
        "order",
        "limits",
    }
)
TRAVERSAL_PLAN_OPTIONAL_FIELDS = frozenset({"filters"})
TRAVERSAL_LIMIT_FIELDS = frozenset(
    {
        "max_depth",
        "max_frontier_width",
        "max_candidates_per_hop",
        "max_total_resources",
        "max_batch_checks",
        "max_wall_clock_millis",
    }
)
GRAPH_FILTER_RESOURCE_KINDS = frozenset(
    {
        "claim_id_in",
        "object_id_in",
        "source_document_id_in",
        "subject_id_in",
    }
)
GRAPH_FILTER_KINDS = GRAPH_FILTER_RESOURCE_KINDS | frozenset({"derivation_in"})
GRAPH_ORDER_KEYS = frozenset(
    {"claim_id", "object_id", "predicate_key", "source_document_id", "subject_id"}
)
GRAPH_ORDER_DIRECTIONS = frozenset({"ascending", "descending"})
GRAPH_FIELDS = frozenset(
    {
        "claim_id",
        "derivation_mode",
        "object_id",
        "predicate_key",
        "provenance_ids",
        "resource_kind",
        "source_document_id",
        "source_version",
        "subject_id",
    }
)
REQUIRED_GRAPH_FIELDS = frozenset(
    {
        "claim_id",
        "derivation_mode",
        "object_id",
        "predicate_key",
        "provenance_ids",
        "source_document_id",
        "source_version",
        "subject_id",
    }
)
GRAPH_RESOURCE_KINDS = frozenset(
    {"chunk", "claim", "derived_artifact", "document", "entity"}
)
PROVIDER_GRAPH_RESOURCE_KINDS = frozenset({"claim", "entity"})
EXPAND_PHASES = frozenset({"entity_to_claim", "claim_to_object"})
GRAPH_OPERATION_TEMPLATE = "claim_traversal_v1"
GRAPH_QUERY_CONTRACT_VERSION = 1
CLAIM_PREDICATE_ALLOWLIST_VERSION = 1
GRAPH_RESOURCE_KIND_ALLOWLIST_VERSION = 1

FAKE_INTRO_ID = "res_00000000000000000000000000000001"
FAKE_DENIED_CANARY_ID = "res_00000000000000000000000000000002"
FAKE_OVERVIEW_ID = "res_00000000000000000000000000000003"
FAKE_LOCAL_FIRST_ID = "res_00000000000000000000000000000004"
FAKE_DENIED_FRONTIER_ID = "res_00000000000000000000000000000005"
FAKE_DENIED_CANARY_DETAIL_ID = "res_00000000000000000000000000000006"
FAKE_DENIED_NEXT_HOP_ID = "res_00000000000000000000000000000007"
FAKE_RUNTIME_ID = "res_00000000000000000000000000000008"
FAKE_PROJECTION_VERSION = "prj_ffffffffffffffffffffffffffffffff"
FAKE_PREDICATE_KEY = "pred_a3b0b7f1948c58d586d3af99fee4704e"
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
            "index": "index_" + FAKE_PROJECTION_VERSION,
            "graph": "graph_" + FAKE_PROJECTION_VERSION,
            "projection": FAKE_PROJECTION_VERSION,
        },
        "serving_state": "serving",
    }


FAKE_CANDIDATES = (
    {"resource": fake_resource(FAKE_INTRO_ID, "entity"), "score": 0.99},
    {"resource": fake_resource(FAKE_DENIED_CANARY_ID, "entity"), "score": 0.98},
    {"resource": fake_resource(FAKE_OVERVIEW_ID, "document"), "score": 0.90},
    {"resource": fake_resource(FAKE_LOCAL_FIRST_ID, "claim"), "score": 0.96},
    {"resource": fake_resource(FAKE_DENIED_FRONTIER_ID, "claim"), "score": 0.95},
    {"resource": fake_resource(FAKE_DENIED_CANARY_DETAIL_ID, "claim"), "score": 0.94},
    {"resource": fake_resource(FAKE_DENIED_NEXT_HOP_ID, "entity"), "score": 0.93},
    {"resource": fake_resource(FAKE_RUNTIME_ID, "entity"), "score": 0.91},
)
FAKE_CANDIDATES_BY_ID = {
    candidate["resource"]["resource_id"]: candidate for candidate in FAKE_CANDIDATES
}
FAKE_RETRIEVE_IDS = (FAKE_INTRO_ID, FAKE_DENIED_CANARY_ID, FAKE_OVERVIEW_ID)
FAKE_CLAIMS = (
    {
        "subject_resource_id": FAKE_INTRO_ID,
        "claim_resource_id": FAKE_LOCAL_FIRST_ID,
        "predicate_key": FAKE_PREDICATE_KEY,
        "object_resource_id": FAKE_RUNTIME_ID,
        "source_document_resource_id": FAKE_OVERVIEW_ID,
        "derivation": "any_support",
    },
    {
        "subject_resource_id": FAKE_INTRO_ID,
        "claim_resource_id": FAKE_DENIED_FRONTIER_ID,
        "predicate_key": FAKE_PREDICATE_KEY,
        "object_resource_id": FAKE_DENIED_NEXT_HOP_ID,
        "source_document_resource_id": FAKE_OVERVIEW_ID,
        "derivation": "all_required",
    },
    {
        "subject_resource_id": FAKE_DENIED_CANARY_ID,
        "claim_resource_id": FAKE_DENIED_CANARY_DETAIL_ID,
        "predicate_key": FAKE_PREDICATE_KEY,
        "object_resource_id": FAKE_DENIED_NEXT_HOP_ID,
        "source_document_resource_id": FAKE_OVERVIEW_ID,
        "derivation": "any_support",
    },
)


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


def load_replayable_build_receipt(
    params: dict[str, Any], out_dir: Path, idempotency_key: str
) -> dict[str, Any] | None:
    receipt = load_build_receipt(out_dir, idempotency_key)
    if receipt is None:
        return None
    namespace = str(params.get("namespace") or "").strip()
    if not projection_isolation_requested(params, out_dir, namespace):
        return receipt
    config_path = receipt.get("config_path")
    if not isinstance(config_path, str) or not config_path:
        return None
    expected_config = out_dir / "kag_config.yaml"
    if not expected_config.is_file() or Path(config_path).resolve() != expected_config.resolve():
        return None
    if not build_checkpoint_path(out_dir, params).is_dir():
        return None
    return receipt


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
        idempotency_key = checkout_projection_idempotency_key(params, base, namespace)
        if idempotency_key:
            repair_params = dict(params)
            repair_params["idempotency_key"] = idempotency_key
            return projection_config(base, out_dir, repair_params)
        raise FileNotFoundError(f"projection KAG config not found; run /build first: {target}")
    return projection_config(base, out_dir, params)


def checkout_projection_idempotency_key(
    params: dict[str, Any], base: Path, namespace: str
) -> str:
    workspace = workspace_path(params)
    if not clean_tracked_workspace_file(workspace, base):
        return ""
    artifacts_dir = workspace / "artifacts"
    current_path = artifacts_dir / "current.json"
    if not clean_tracked_workspace_file(workspace, current_path):
        return ""
    try:
        current_data = current_path.read_bytes()
        current = json.loads(current_data)
    except (OSError, json.JSONDecodeError):
        return ""
    if not isinstance(current, dict) or current.get("version") != 2:
        return ""
    projection_id = current.get("projection_id")
    projection_version = current.get("projection_version")
    manifest_digest = current.get("manifest_sha256")
    if (
        not isinstance(projection_id, str)
        or re.fullmatch(r"prj_[0-9a-f]{32}", projection_id) is None
        or projection_version != projection_id
        or not isinstance(manifest_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", manifest_digest) is None
    ):
        return ""
    manifest_path = artifacts_dir / "bundles" / projection_id / "manifest.json"
    if not clean_tracked_workspace_file(workspace, manifest_path):
        return ""
    try:
        manifest_data = manifest_path.read_bytes()
        manifest = json.loads(manifest_data)
    except (OSError, json.JSONDecodeError):
        return ""
    if hashlib.sha256(manifest_data).hexdigest() != manifest_digest:
        return ""
    if (
        not isinstance(manifest, dict)
        or manifest.get("version") != 2
        or manifest.get("projection_id") != projection_id
        or manifest.get("projection_version") != projection_version
        or manifest.get("namespace") != namespace
    ):
        return ""
    return f"kag-build-{projection_version}"


def clean_tracked_workspace_file(workspace: Path, path: Path) -> bool:
    try:
        relative = path.resolve().relative_to(workspace.resolve())
    except (OSError, ValueError):
        return False
    if not path.is_file() or path.is_symlink():
        return False
    relative_name = relative.as_posix()
    tracked = subprocess.run(
        ["git", "-C", str(workspace), "ls-files", "--error-unmatch", "--", relative_name],
        text=True,
        capture_output=True,
        check=False,
    )
    if tracked.returncode != 0:
        return False
    unchanged = subprocess.run(
        ["git", "-C", str(workspace), "diff", "--quiet", "HEAD", "--", relative_name],
        text=True,
        capture_output=True,
        check=False,
    )
    return unchanged.returncode == 0


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


def required_authorization_token(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise AdapterRequestError(f"{field} must be a non-empty string")
    if value.strip() != value:
        raise AdapterRequestError(f"{field} contains leading or trailing whitespace")
    if any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in value):
        raise AdapterRequestError(f"{field} contains control characters")
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


def validate_allowed_fields(
    value: dict[str, Any],
    required: frozenset[str],
    optional: frozenset[str],
    field: str,
) -> None:
    actual = set(value)
    missing = sorted(required - actual)
    unexpected = sorted(actual - required - optional)
    if not missing and not unexpected:
        return
    details: list[str] = []
    if missing:
        details.append("missing " + ", ".join(missing))
    if unexpected:
        details.append("unexpected " + ", ".join(unexpected))
    raise AdapterRequestError(f"{field} has invalid fields ({'; '.join(details)})")


def required_integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AdapterRequestError(f"{field} must be an integer")
    return value


def full_expansion_scan_limit(params: dict[str, Any]) -> int:
    value = required_integer(params.get("limit"), "limit")
    if value != MAX_PRIMITIVE_ITEMS:
        raise AdapterRequestError(
            f"limit must equal the full expansion scan limit of {MAX_PRIMITIVE_ITEMS}"
        )
    return value


def full_discovery_scan_limit(params: dict[str, Any]) -> int:
    value = required_integer(params.get("limit"), "limit")
    if value != MAX_PRIMITIVE_ITEMS:
        raise AdapterRequestError(
            f"limit must equal the full discovery scan limit of {MAX_PRIMITIVE_ITEMS}"
        )
    return value


def validate_sorted_unique_strings(
    value: Any,
    field: str,
    *,
    minimum: int,
    maximum: int,
) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise AdapterRequestError(
            f"{field} must contain between {minimum} and {maximum} values"
        )
    normalized = [
        required_authorization_token(item, f"{field}[{index}]")
        for index, item in enumerate(value)
    ]
    if normalized != sorted(set(normalized)):
        raise AdapterRequestError(f"{field} must be unique and sorted")
    return normalized


def validate_graph_filter(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AdapterRequestError(f"{field} must be an object")
    kind = required_authorization_token(value.get("kind"), f"{field}.kind")
    if kind in GRAPH_FILTER_RESOURCE_KINDS:
        validate_exact_fields(value, frozenset({"kind", "resource_ids"}), field)
        resource_ids = validate_sorted_unique_strings(
            value.get("resource_ids"),
            f"{field}.resource_ids",
            minimum=1,
            maximum=256,
        )
        for index, resource_id in enumerate(resource_ids):
            if not RESOURCE_ID_RE.fullmatch(resource_id):
                raise AdapterRequestError(
                    f"{field}.resource_ids[{index}] must be an opaque res_ identifier"
                )
        return {"kind": kind, "resource_ids": resource_ids}
    if kind == "derivation_in":
        validate_exact_fields(value, frozenset({"kind", "derivations"}), field)
        derivations = validate_sorted_unique_strings(
            value.get("derivations"),
            f"{field}.derivations",
            minimum=1,
            maximum=2,
        )
        if any(
            derivation not in {"all_required", "any_support"}
            for derivation in derivations
        ):
            raise AdapterRequestError(f"{field}.derivations is unsupported")
        return {"kind": kind, "derivations": derivations}
    raise AdapterRequestError(f"{field}.kind is unsupported")


def validate_graph_order(value: Any, field: str, priority: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AdapterRequestError(f"{field} must be an object")
    validate_exact_fields(value, frozenset({"key", "direction", "priority"}), field)
    key = required_authorization_token(value.get("key"), f"{field}.key")
    direction = required_authorization_token(
        value.get("direction"), f"{field}.direction"
    )
    actual_priority = required_integer(value.get("priority"), f"{field}.priority")
    if key not in GRAPH_ORDER_KEYS:
        raise AdapterRequestError(f"{field}.key is unsupported")
    if direction not in GRAPH_ORDER_DIRECTIONS:
        raise AdapterRequestError(f"{field}.direction is unsupported")
    if actual_priority != priority:
        raise AdapterRequestError("operation.parameters.order priorities are not normalized")
    return {"key": key, "direction": direction, "priority": actual_priority}


def validate_traversal_limits(value: Any, start_count: int) -> dict[str, int]:
    field = "operation.parameters.limits"
    if not isinstance(value, dict):
        raise AdapterRequestError(f"{field} must be an object")
    validate_exact_fields(value, TRAVERSAL_LIMIT_FIELDS, field)
    limits = {
        name: required_integer(value.get(name), f"{field}.{name}")
        for name in sorted(TRAVERSAL_LIMIT_FIELDS)
    }
    if not 1 <= limits["max_depth"] <= 8:
        raise AdapterRequestError(f"{field}.max_depth is unsupported for expansion")
    if not 1 <= limits["max_frontier_width"] <= 256:
        raise AdapterRequestError(f"{field}.max_frontier_width is invalid")
    if not 1 <= limits["max_candidates_per_hop"] <= 512:
        raise AdapterRequestError(f"{field}.max_candidates_per_hop is invalid")
    if limits["max_frontier_width"] > MAX_PRIMITIVE_ITEMS:
        raise AdapterRequestError(f"{field}.max_frontier_width exceeds provider limit")
    if limits["max_candidates_per_hop"] > MAX_PRIMITIVE_ITEMS:
        raise AdapterRequestError(
            f"{field}.max_candidates_per_hop exceeds provider limit"
        )
    if not start_count <= limits["max_total_resources"] <= 2048:
        raise AdapterRequestError(f"{field}.max_total_resources is invalid")
    if not 1 <= limits["max_batch_checks"] <= 128:
        raise AdapterRequestError(f"{field}.max_batch_checks is invalid")
    if not 1 <= limits["max_wall_clock_millis"] <= 30_000:
        raise AdapterRequestError(f"{field}.max_wall_clock_millis is invalid")
    return limits


def validate_graph_operation(
    value: Any,
    *,
    expected_projection: str | None = None,
    expected_identity_version: int | None = None,
) -> dict[str, Any]:
    field = "operation"
    if not isinstance(value, dict):
        raise AdapterRequestError(f"{field} must be an object")
    validate_exact_fields(value, GRAPH_OPERATION_FIELDS, field)
    if required_integer(value.get("version"), f"{field}.version") != GRAPH_QUERY_CONTRACT_VERSION:
        raise AdapterRequestError(f"{field}.version is unsupported")
    template = required_authorization_token(value.get("template"), f"{field}.template")
    if template != GRAPH_OPERATION_TEMPLATE:
        raise AdapterRequestError(f"{field}.template is unsupported")
    plan = value.get("parameters")
    if not isinstance(plan, dict):
        raise AdapterRequestError(f"{field}.parameters must be an object")
    validate_allowed_fields(
        plan,
        TRAVERSAL_PLAN_REQUIRED_FIELDS,
        TRAVERSAL_PLAN_OPTIONAL_FIELDS,
        f"{field}.parameters",
    )
    if required_integer(plan.get("version"), f"{field}.parameters.version") != GRAPH_QUERY_CONTRACT_VERSION:
        raise AdapterRequestError(f"{field}.parameters.version is unsupported")
    if (
        required_integer(
            plan.get("predicate_allowlist_version"),
            f"{field}.parameters.predicate_allowlist_version",
        )
        != CLAIM_PREDICATE_ALLOWLIST_VERSION
    ):
        raise AdapterRequestError(
            f"{field}.parameters.predicate_allowlist_version is unsupported"
        )
    if (
        required_integer(
            plan.get("resource_kind_allowlist_version"),
            f"{field}.parameters.resource_kind_allowlist_version",
        )
        != GRAPH_RESOURCE_KIND_ALLOWLIST_VERSION
    ):
        raise AdapterRequestError(
            f"{field}.parameters.resource_kind_allowlist_version is unsupported"
        )
    projection_version = required_authorization_token(
        plan.get("projection_version"), f"{field}.parameters.projection_version"
    )
    if not PROJECTION_ID_RE.fullmatch(projection_version):
        raise AdapterRequestError(f"{field}.parameters.projection_version is invalid")
    if expected_projection is not None and projection_version != expected_projection:
        raise AdapterRequestError(
            f"{field}.parameters.projection_version does not match the selected projection"
        )
    identity_version = required_integer(
        plan.get("identity_version"), f"{field}.parameters.identity_version"
    )
    if identity_version != GRAPH_BINDING_CONTRACT_VERSION:
        raise AdapterRequestError(f"{field}.parameters.identity_version is unsupported")
    if (
        expected_identity_version is not None
        and identity_version != expected_identity_version
    ):
        raise AdapterRequestError(
            f"{field}.parameters.identity_version does not match the selected identity contract"
        )
    start_resource_ids = validate_sorted_unique_strings(
        plan.get("start_resource_ids"),
        f"{field}.parameters.start_resource_ids",
        minimum=1,
        maximum=64,
    )
    for index, resource_id in enumerate(start_resource_ids):
        if not RESOURCE_ID_RE.fullmatch(resource_id):
            raise AdapterRequestError(
                f"{field}.parameters.start_resource_ids[{index}] must be an opaque res_ identifier"
            )
    predicate_keys = validate_sorted_unique_strings(
        plan.get("predicate_keys"),
        f"{field}.parameters.predicate_keys",
        minimum=1,
        maximum=len(SUPPORTED_CLAIM_PREDICATE_KEYS),
    )
    for index, predicate_key in enumerate(predicate_keys):
        if (
            not CLAIM_PREDICATE_KEY_RE.fullmatch(predicate_key)
            or predicate_key not in SUPPORTED_CLAIM_PREDICATE_KEYS
        ):
            raise AdapterRequestError(
                f"{field}.parameters.predicate_keys[{index}] is not declared by the active allowlist"
            )
    resource_kinds = validate_sorted_unique_strings(
        plan.get("resource_kinds"),
        f"{field}.parameters.resource_kinds",
        minimum=1,
        maximum=len(GRAPH_RESOURCE_KINDS),
    )
    if any(kind not in GRAPH_RESOURCE_KINDS for kind in resource_kinds):
        raise AdapterRequestError(f"{field}.parameters.resource_kinds is unsupported")
    if any(kind not in PROVIDER_GRAPH_RESOURCE_KINDS for kind in resource_kinds):
        raise AdapterRequestError(
            f"{field}.parameters.resource_kinds is unsupported by the provider"
        )
    direction = required_authorization_token(
        plan.get("direction"), f"{field}.parameters.direction"
    )
    if direction != "outbound":
        raise AdapterRequestError(f"{field}.parameters.direction is unsupported")
    fields = validate_sorted_unique_strings(
        plan.get("fields"),
        f"{field}.parameters.fields",
        minimum=1,
        maximum=len(GRAPH_FIELDS),
    )
    if any(item not in GRAPH_FIELDS for item in fields) or not REQUIRED_GRAPH_FIELDS.issubset(fields):
        raise AdapterRequestError(f"{field}.parameters.fields is unsupported")
    filter_values = plan.get("filters", [])
    if not isinstance(filter_values, list) or len(filter_values) > 5:
        raise AdapterRequestError(f"{field}.parameters.filters is invalid")
    filters = [
        validate_graph_filter(item, f"{field}.parameters.filters[{index}]")
        for index, item in enumerate(filter_values)
    ]
    filter_kinds = [item["kind"] for item in filters]
    if filter_kinds != sorted(set(filter_kinds)):
        raise AdapterRequestError(f"{field}.parameters.filters must be unique and sorted")
    order_values = plan.get("order")
    if not isinstance(order_values, list) or not 1 <= len(order_values) <= 5:
        raise AdapterRequestError(f"{field}.parameters.order is invalid")
    order = [
        validate_graph_order(item, f"{field}.parameters.order[{index}]", index)
        for index, item in enumerate(order_values)
    ]
    order_keys = [item["key"] for item in order]
    if len(order_keys) != len(set(order_keys)) or "claim_id" not in order_keys:
        raise AdapterRequestError(f"{field}.parameters.order is not normalized")
    limits = validate_traversal_limits(plan.get("limits"), len(start_resource_ids))
    return {
        "version": GRAPH_QUERY_CONTRACT_VERSION,
        "template": template,
        "parameters": {
            "version": GRAPH_QUERY_CONTRACT_VERSION,
            "predicate_allowlist_version": CLAIM_PREDICATE_ALLOWLIST_VERSION,
            "resource_kind_allowlist_version": GRAPH_RESOURCE_KIND_ALLOWLIST_VERSION,
            "projection_version": projection_version,
            "identity_version": identity_version,
            "start_resource_ids": start_resource_ids,
            "predicate_keys": predicate_keys,
            "resource_kinds": resource_kinds,
            "direction": direction,
            "fields": fields,
            "filters": filters,
            "order": order,
            "limits": limits,
        },
    }


def validate_expand_contract(
    params: dict[str, Any],
    *,
    expected_projection: str | None = None,
    expected_identity_version: int | None = None,
) -> tuple[dict[str, Any], str]:
    validate_allowed_fields(
        params,
        frozenset({"authorization", "operation", "phase", "frontier", "limit"}),
        PRIMITIVE_TRANSPORT_FIELDS,
        "expand params",
    )
    operation = validate_graph_operation(
        params.get("operation"),
        expected_projection=expected_projection,
        expected_identity_version=expected_identity_version,
    )
    phase = required_authorization_token(params.get("phase"), "phase")
    if phase not in EXPAND_PHASES:
        raise AdapterRequestError("phase is unsupported")
    return operation, phase


def validate_authorization(value: Any) -> dict[str, Any]:
    field = "authorization"
    if not isinstance(value, dict):
        raise AdapterRequestError(f"{field} must be an object")
    actual = set(value)
    missing = sorted(AUTHORIZATION_REQUIRED_FIELDS - actual)
    unexpected = sorted(
        actual - AUTHORIZATION_REQUIRED_FIELDS - AUTHORIZATION_OPTIONAL_FIELDS
    )
    if missing or unexpected:
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        raise AdapterRequestError(
            f"{field} has invalid fields ({'; '.join(details)})"
        )

    normalized = {
        name: required_authorization_token(value.get(name), f"{field}.{name}")
        for name in sorted(AUTHORIZATION_REQUIRED_FIELDS)
    }
    if normalized["version"] != AUTHORIZATION_CONTEXT_VERSION:
        raise AdapterRequestError(
            f"{field}.version must be {AUTHORIZATION_CONTEXT_VERSION}"
        )
    if normalized["consistency"] not in AUTHORIZATION_CONSISTENCY_VALUES:
        raise AdapterRequestError(f"{field}.consistency is unsupported")
    for name in sorted(AUTHORIZATION_OPTIONAL_FIELDS):
        if name in value:
            normalized[name] = required_authorization_token(
                value.get(name), f"{field}.{name}"
            )
    return normalized


def require_authorization_scope(
    resource: dict[str, Any], authorization: dict[str, Any], field: str
) -> None:
    if resource["tenant_id"] != authorization["tenant_id"]:
        raise AdapterRequestError(
            f"{field}.tenant_id is outside authorization tenant_id"
        )
    if resource["knowledge_base_id"] != authorization["knowledge_base_id"]:
        raise AdapterRequestError(
            f"{field}.knowledge_base_id is outside authorization knowledge_base_id"
        )


def validate_resource(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AdapterRequestError(f"{field} must be an object")
    validate_exact_fields(value, RESOURCE_FIELDS, field)
    resource_id = required_authorization_token(
        value.get("resource_id"), f"{field}.resource_id"
    )
    if not RESOURCE_ID_RE.fullmatch(resource_id):
        raise AdapterRequestError(f"{field}.resource_id must be an opaque res_ identifier")
    resource_type = required_authorization_token(value.get("type"), f"{field}.type")
    if resource_type not in RESOURCE_TYPES:
        raise AdapterRequestError(f"{field}.type is unsupported")
    tenant_id = required_authorization_token(value.get("tenant_id"), f"{field}.tenant_id")
    knowledge_base_id = required_authorization_token(
        value.get("knowledge_base_id"), f"{field}.knowledge_base_id"
    )
    authz_object = required_authorization_token(
        value.get("authz_object"), f"{field}.authz_object"
    )
    authorization_resource_id = required_authorization_token(
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
    content_digest = required_authorization_token(
        value.get("content_digest"), f"{field}.content_digest"
    )
    if not CONTENT_DIGEST_RE.fullmatch(content_digest):
        raise AdapterRequestError(f"{field}.content_digest must be a sha256 digest")
    versions = value.get("versions")
    if not isinstance(versions, dict):
        raise AdapterRequestError(f"{field}.versions must be an object")
    validate_exact_fields(versions, RESOURCE_VERSION_FIELDS, f"{field}.versions")
    normalized_versions = {
        name: required_authorization_token(
            versions.get(name), f"{field}.versions.{name}"
        )
        for name in sorted(RESOURCE_VERSION_FIELDS)
    }
    serving_state = required_authorization_token(
        value.get("serving_state"), f"{field}.serving_state"
    )
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


def expected_graph_object_id(
    projection_version: str,
    resource_id: str,
    contract_version: int = GRAPH_BINDING_CONTRACT_VERSION,
) -> str:
    identity = (
        f"{contract_version}\0{projection_version}\0{resource_id}"
    )
    return "kg_" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]


def require_artifact_directory(path: Path, field: str) -> None:
    if path.is_symlink() or not path.is_dir():
        raise AdapterRequestError(
            f"{field} must be a real directory", INVALID_GRAPH_BINDING_CODE
        )


def read_artifact_file(path: Path, root: Path, field: str, max_bytes: int) -> bytes:
    try:
        resolved_root = root.resolve(strict=True)
        resolved = path.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise AdapterRequestError(
            f"{field} is outside the selected artifact bundle",
            INVALID_GRAPH_BINDING_CODE,
        ) from exc
    if path.is_symlink() or not path.is_file():
        raise AdapterRequestError(
            f"{field} must be a regular file", INVALID_GRAPH_BINDING_CODE
        )
    current = path.parent
    while current != root:
        if current.is_symlink():
            raise AdapterRequestError(
                f"{field} has a symlinked parent", INVALID_GRAPH_BINDING_CODE
            )
        if root not in current.parents:
            break
        current = current.parent
    try:
        with path.open("rb") as stream:
            data = stream.read(max_bytes + 1)
    except OSError as exc:
        raise AdapterRequestError(
            f"cannot read {field}: {exc}", INVALID_GRAPH_BINDING_CODE
        ) from exc
    if len(data) > max_bytes:
        raise AdapterRequestError(
            f"{field} exceeds the file size limit", INVALID_GRAPH_BINDING_CODE
        )
    return data


def decode_artifact_object(data: bytes, field: str) -> dict[str, Any]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate object field {key!r}")
            value[key] = item
        return value

    try:
        value = json.loads(data, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AdapterRequestError(
            f"{field} is not valid JSON: {exc}", INVALID_GRAPH_BINDING_CODE
        ) from exc
    if not isinstance(value, dict):
        raise AdapterRequestError(
            f"{field} must be an object", INVALID_GRAPH_BINDING_CODE
        )
    return value


def validate_artifact_descriptor(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AdapterRequestError(
            f"{field} must be an object", INVALID_GRAPH_BINDING_CODE
        )
    validate_exact_fields(value, ARTIFACT_DESCRIPTOR_FIELDS, field)
    path = required_authorization_token(value.get("path"), f"{field}.path")
    if path in {".", ".."} or "/" in path or "\\" in path:
        raise AdapterRequestError(
            f"{field}.path must be a bundle file name", INVALID_GRAPH_BINDING_CODE
        )
    sha256 = required_authorization_token(value.get("sha256"), f"{field}.sha256")
    if not SHA256_RE.fullmatch(sha256):
        raise AdapterRequestError(
            f"{field}.sha256 must be a SHA-256 digest", INVALID_GRAPH_BINDING_CODE
        )
    count = value.get("count")
    size_bytes = value.get("size_bytes")
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or count < 0
        or isinstance(size_bytes, bool)
        or not isinstance(size_bytes, int)
        or size_bytes < 0
    ):
        raise AdapterRequestError(
            f"{field} has an invalid count or size", INVALID_GRAPH_BINDING_CODE
        )
    return {"path": path, "sha256": sha256, "count": count, "size_bytes": size_bytes}


def verified_jsonl_rows(
    bundle_dir: Path, descriptor: dict[str, Any], field: str
) -> list[dict[str, Any]]:
    if descriptor["size_bytes"] > MAX_GRAPH_BINDING_FILE_BYTES:
        raise AdapterRequestError(
            f"{field} exceeds the graph binding file limit",
            INVALID_GRAPH_BINDING_CODE,
        )
    data = read_artifact_file(
        bundle_dir / descriptor["path"],
        bundle_dir,
        field,
        MAX_GRAPH_BINDING_FILE_BYTES,
    )
    if hashlib.sha256(data).hexdigest() != descriptor["sha256"]:
        raise AdapterRequestError(
            f"{field} digest does not match the bundle manifest",
            INVALID_GRAPH_BINDING_CODE,
        )
    if len(data) != descriptor["size_bytes"]:
        raise AdapterRequestError(
            f"{field} size does not match the bundle manifest",
            INVALID_GRAPH_BINDING_CODE,
        )
    if data and not data.endswith(b"\n"):
        raise AdapterRequestError(
            f"{field} must end with a newline", INVALID_GRAPH_BINDING_CODE
        )
    lines = data.splitlines()
    if len(lines) != descriptor["count"]:
        raise AdapterRequestError(
            f"{field} count does not match the bundle manifest",
            INVALID_GRAPH_BINDING_CODE,
        )
    rows: list[dict[str, Any]] = []
    for index, line in enumerate(lines):
        if len(line) > MAX_GRAPH_BINDING_LINE_BYTES:
            raise AdapterRequestError(
                f"{field}[{index}] exceeds the graph binding row limit",
                INVALID_GRAPH_BINDING_CODE,
            )
        if not line.strip():
            raise AdapterRequestError(
                f"{field}[{index}] is blank", INVALID_GRAPH_BINDING_CODE
            )
        rows.append(decode_artifact_object(line, f"{field}[{index}]"))
    return rows


def validate_graph_binding_row(
    value: dict[str, Any],
    field: str,
    authorization: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    validate_exact_fields(value, GRAPH_BINDING_FIELDS, field)
    contract_version = manifest["graph_binding_contract_version"]
    if value.get("version") != contract_version:
        raise AdapterRequestError(
            f"{field}.version does not match the selected contract",
            INVALID_GRAPH_BINDING_CODE,
        )
    graph_object_id = required_authorization_token(
        value.get("graph_object_id"), f"{field}.graph_object_id"
    )
    if not GRAPH_OBJECT_ID_RE.fullmatch(graph_object_id):
        raise AdapterRequestError(
            f"{field}.graph_object_id must be an opaque kg_ identifier",
            INVALID_GRAPH_BINDING_CODE,
        )
    resource = validate_resource(value.get("resource"), f"{field}.resource")
    require_authorization_scope(resource, authorization, f"{field}.resource")
    versions = resource["versions"]
    expected_versions = {
        "source": manifest["source_snapshot"]["version"],
        "acl": manifest["authz_version"],
        "index": "index_" + manifest["projection_version"],
        "graph": "graph_" + manifest["projection_version"],
        "projection": manifest["projection_version"],
    }
    for name, expected in expected_versions.items():
        if versions[name] != expected:
            raise AdapterRequestError(
                f"{field}.resource.versions.{name} does not match the selected projection",
                INVALID_GRAPH_BINDING_CODE,
            )
    expected_id = expected_graph_object_id(
        manifest["projection_version"], resource["resource_id"], contract_version
    )
    if graph_object_id != expected_id:
        raise AdapterRequestError(
            f"{field}.graph_object_id does not match the exact serving resource",
            INVALID_GRAPH_BINDING_CODE,
        )
    return {
        "version": contract_version,
        "graph_object_id": graph_object_id,
        "resource": resource,
    }


def validate_claim_provenance_ids(
    value: Any, resources: dict[str, dict[str, Any]], field: str
) -> list[str]:
    if not isinstance(value, list) or not value:
        raise AdapterRequestError(
            f"{field} is required", INVALID_GRAPH_BINDING_CODE
        )
    normalized: list[str] = []
    for index, graph_object_id in enumerate(value):
        graph_object_id = required_authorization_token(
            graph_object_id, f"{field}[{index}]"
        )
        if (
            not GRAPH_OBJECT_ID_RE.fullmatch(graph_object_id)
            or graph_object_id not in resources
        ):
            raise AdapterRequestError(
                f"{field}[{index}] is not graph-bound",
                INVALID_GRAPH_BINDING_CODE,
            )
        normalized.append(graph_object_id)
    if normalized != sorted(set(normalized)):
        raise AdapterRequestError(
            f"{field} must be unique and sorted", INVALID_GRAPH_BINDING_CODE
        )
    return normalized


def validate_claim_provenance_resource_ids(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise AdapterRequestError(
            f"{field} is required", INVALID_GRAPH_BINDING_CODE
        )
    normalized: list[str] = []
    for index, resource_id in enumerate(value):
        resource_id = required_authorization_token(resource_id, f"{field}[{index}]")
        if not RESOURCE_ID_RE.fullmatch(resource_id):
            raise AdapterRequestError(
                f"{field}[{index}] must be an opaque res_ identifier",
                INVALID_GRAPH_BINDING_CODE,
            )
        normalized.append(resource_id)
    if normalized != sorted(set(normalized)):
        raise AdapterRequestError(
            f"{field} must be unique and sorted", INVALID_GRAPH_BINDING_CODE
        )
    return normalized


def validate_claim_provenance_mapping(
    graph_ids: list[str],
    stable_ids: list[str],
    resources: dict[str, dict[str, Any]],
    source_resource_id: str,
    field: str,
) -> None:
    graph_resource_ids: list[str] = []
    for graph_object_id in graph_ids:
        support = resources[graph_object_id]
        if support["type"] not in {"document", "chunk"} or (
            support["resource_id"] != source_resource_id
            and support["authorization_resource_id"] != source_resource_id
        ):
            raise AdapterRequestError(
                f"{field} is outside the source document",
                INVALID_GRAPH_BINDING_CODE,
            )
        graph_resource_ids.append(support["resource_id"])
    if sorted(graph_resource_ids) != stable_ids:
        raise AdapterRequestError(
            f"{field} stable identities do not match graph bindings",
            INVALID_GRAPH_BINDING_CODE,
        )


def derived_v1_claim_support_key(
    claim_resource_id: str, derivation: str, provenance_resource_ids: list[str]
) -> str:
    source_identity = (
        f"v1:{claim_resource_id}:{derivation}:"
        + ",".join(provenance_resource_ids)
    )
    return "sup_" + hashlib.sha256(source_identity.encode("utf-8")).hexdigest()[:32]


def upgrade_v1_claim_supports(
    claim_resource_id: str,
    derivation: str,
    provenance: list[str],
    provenance_resource_ids: list[str],
    resources: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if derivation == "all_required":
        return [
            {
                "support_key": derived_v1_claim_support_key(
                    claim_resource_id, derivation, provenance_resource_ids
                ),
                "provenance": list(provenance),
                "provenance_resource_ids": list(provenance_resource_ids),
            }
        ]
    supports = []
    for graph_object_id in provenance:
        resource_id = resources[graph_object_id]["resource_id"]
        supports.append(
            {
                "support_key": derived_v1_claim_support_key(
                    claim_resource_id, derivation, [resource_id]
                ),
                "provenance": [graph_object_id],
                "provenance_resource_ids": [resource_id],
            }
        )
    return sorted(supports, key=lambda support: support["support_key"])


def validate_claim_binding_rows(
    rows: list[dict[str, Any]],
    resources: dict[str, dict[str, Any]],
    contract_version: int,
) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    previous = ""
    for index, value in enumerate(rows):
        field = f"claim_bindings[{index}]"
        expected_fields = (
            CLAIM_BINDING_V1_FIELDS
            if contract_version == GRAPH_BINDING_CONTRACT_VERSION_V1
            else CLAIM_BINDING_FIELDS
        )
        validate_exact_fields(value, expected_fields, field)
        if value.get("version") != contract_version:
            raise AdapterRequestError(
                f"{field}.version does not match the selected contract",
                INVALID_GRAPH_BINDING_CODE,
            )
        normalized: dict[str, Any] = {"version": GRAPH_BINDING_CONTRACT_VERSION}
        for name in ("claim", "subject", "object", "source_document"):
            graph_object_id = required_authorization_token(
                value.get(name), f"{field}.{name}"
            )
            if not GRAPH_OBJECT_ID_RE.fullmatch(graph_object_id) or graph_object_id not in resources:
                raise AdapterRequestError(
                    f"{field}.{name} is not present in graph_bindings",
                    INVALID_GRAPH_BINDING_CODE,
                )
            normalized[name] = graph_object_id
        predicate_key = required_authorization_token(
            value.get("predicate_key"), f"{field}.predicate_key"
        )
        if not CLAIM_PREDICATE_KEY_RE.fullmatch(predicate_key):
            raise AdapterRequestError(
                f"{field}.predicate_key must be an opaque pred_ identifier",
                INVALID_GRAPH_BINDING_CODE,
            )
        predicate_is_supported = predicate_key in SUPPORTED_CLAIM_PREDICATE_KEYS
        if (
            not predicate_is_supported
            and contract_version != GRAPH_BINDING_CONTRACT_VERSION_V1
        ):
            raise AdapterRequestError(
                f"{field}.predicate_key is not declared by the active allowlist",
                INVALID_GRAPH_BINDING_CODE,
            )
        normalized["predicate_key"] = predicate_key
        derivation = required_authorization_token(
            value.get("derivation"), f"{field}.derivation"
        )
        if derivation not in {"any_support", "all_required"}:
            raise AdapterRequestError(
                f"{field}.derivation is unsupported", INVALID_GRAPH_BINDING_CODE
            )
        normalized["derivation"] = derivation
        if contract_version == GRAPH_BINDING_CONTRACT_VERSION_V1:
            normalized["subject_resource_id"] = resources[normalized["subject"]][
                "resource_id"
            ]
            normalized["object_resource_id"] = resources[normalized["object"]][
                "resource_id"
            ]
            normalized["source_document_resource_id"] = resources[
                normalized["source_document"]
            ]["resource_id"]
            normalized["source_version"] = resources[normalized["source_document"]][
                "versions"
            ]["source"]
        else:
            for name in (
                "subject_resource_id",
                "object_resource_id",
                "source_document_resource_id",
            ):
                resource_id = required_authorization_token(
                    value.get(name), f"{field}.{name}"
                )
                if not RESOURCE_ID_RE.fullmatch(resource_id):
                    raise AdapterRequestError(
                        f"{field}.{name} must be an opaque res_ identifier",
                        INVALID_GRAPH_BINDING_CODE,
                    )
                normalized[name] = resource_id
            normalized["source_version"] = required_authorization_token(
                value.get("source_version"), f"{field}.source_version"
            )
        normalized_provenance = validate_claim_provenance_ids(
            value.get("provenance"), resources, f"{field}.provenance"
        )
        normalized["provenance"] = normalized_provenance
        if contract_version == GRAPH_BINDING_CONTRACT_VERSION_V1:
            normalized_provenance_resource_ids = sorted(
                resources[graph_object_id]["resource_id"]
                for graph_object_id in normalized_provenance
            )
        else:
            normalized_provenance_resource_ids = validate_claim_provenance_resource_ids(
                value.get("provenance_resource_ids"),
                f"{field}.provenance_resource_ids",
            )
        normalized["provenance_resource_ids"] = normalized_provenance_resource_ids
        supports = value.get("supports")
        if contract_version == GRAPH_BINDING_CONTRACT_VERSION_V1:
            supports = upgrade_v1_claim_supports(
                resources[normalized["claim"]]["resource_id"],
                derivation,
                normalized_provenance,
                normalized_provenance_resource_ids,
                resources,
            )
        if not isinstance(supports, list) or not supports:
            raise AdapterRequestError(
                f"{field}.supports is required", INVALID_GRAPH_BINDING_CODE
            )
        normalized_supports: list[dict[str, Any]] = []
        previous_support_key = ""
        grouped_graph_ids: list[str] = []
        grouped_resource_ids: list[str] = []
        for support_index, support in enumerate(supports):
            support_field = f"{field}.supports[{support_index}]"
            if not isinstance(support, dict):
                raise AdapterRequestError(
                    f"{support_field} must be an object",
                    INVALID_GRAPH_BINDING_CODE,
                )
            validate_exact_fields(support, CLAIM_SUPPORT_FIELDS, support_field)
            support_key = required_authorization_token(
                support.get("support_key"), f"{support_field}.support_key"
            )
            if not CLAIM_SUPPORT_KEY_RE.fullmatch(support_key):
                raise AdapterRequestError(
                    f"{support_field}.support_key must be an opaque sup_ identifier",
                    INVALID_GRAPH_BINDING_CODE,
                )
            if support_key <= previous_support_key:
                raise AdapterRequestError(
                    f"{field}.supports must be unique and sorted by support_key",
                    INVALID_GRAPH_BINDING_CODE,
                )
            previous_support_key = support_key
            support_provenance = validate_claim_provenance_ids(
                support.get("provenance"),
                resources,
                f"{support_field}.provenance",
            )
            support_resource_ids = validate_claim_provenance_resource_ids(
                support.get("provenance_resource_ids"),
                f"{support_field}.provenance_resource_ids",
            )
            if len(support_provenance) != len(support_resource_ids):
                raise AdapterRequestError(
                    f"{support_field} graph and stable provenance counts differ",
                    INVALID_GRAPH_BINDING_CODE,
                )
            normalized_supports.append(
                {
                    "support_key": support_key,
                    "provenance": support_provenance,
                    "provenance_resource_ids": support_resource_ids,
                }
            )
            grouped_graph_ids.extend(support_provenance)
            grouped_resource_ids.extend(support_resource_ids)
        if sorted(set(grouped_graph_ids)) != normalized_provenance or sorted(
            set(grouped_resource_ids)
        ) != normalized_provenance_resource_ids:
            raise AdapterRequestError(
                f"{field}.supports does not match flattened provenance",
                INVALID_GRAPH_BINDING_CODE,
            )
        normalized["supports"] = normalized_supports
        if normalized["claim"] <= previous:
            raise AdapterRequestError(
                "claim_bindings must be unique and sorted by claim",
                INVALID_GRAPH_BINDING_CODE,
            )
        previous = normalized["claim"]
        claim_resource = resources[normalized["claim"]]
        subject_resource = resources[normalized["subject"]]
        object_resource = resources[normalized["object"]]
        source_resource = resources[normalized["source_document"]]
        if claim_resource["type"] != "claim":
            raise AdapterRequestError(f"{field}.claim must reference a claim", INVALID_GRAPH_BINDING_CODE)
        if subject_resource["type"] != "entity" or object_resource["type"] != "entity":
            raise AdapterRequestError(f"{field} endpoints must reference entities", INVALID_GRAPH_BINDING_CODE)
        if source_resource["type"] != "document":
            raise AdapterRequestError(f"{field}.source_document must reference a document", INVALID_GRAPH_BINDING_CODE)
        if subject_resource["resource_id"] != normalized["subject_resource_id"]:
            raise AdapterRequestError(
                f"{field}.subject_resource_id does not match its graph binding",
                INVALID_GRAPH_BINDING_CODE,
            )
        if object_resource["resource_id"] != normalized["object_resource_id"]:
            raise AdapterRequestError(
                f"{field}.object_resource_id does not match its graph binding",
                INVALID_GRAPH_BINDING_CODE,
            )
        if (
            source_resource["resource_id"]
            != normalized["source_document_resource_id"]
            or source_resource["versions"]["source"] != normalized["source_version"]
        ):
            raise AdapterRequestError(
                f"{field} source identity or version does not match its graph binding",
                INVALID_GRAPH_BINDING_CODE,
            )
        source_id = source_resource["resource_id"]
        validate_claim_provenance_mapping(
            normalized_provenance,
            normalized_provenance_resource_ids,
            resources,
            source_id,
            f"{field}.provenance",
        )
        for support_index, support in enumerate(normalized_supports):
            validate_claim_provenance_mapping(
                support["provenance"],
                support["provenance_resource_ids"],
                resources,
                source_id,
                f"{field}.supports[{support_index}].provenance",
            )
        if predicate_is_supported:
            claims.append(normalized)
    return claims


def load_current_graph_contract(
    params: dict[str, Any], authorization: dict[str, Any]
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]], int]:
    try:
        return _load_current_graph_contract(params, authorization)
    except AdapterRequestError as exc:
        raise AdapterRequestError(
            "selected graph binding contract is invalid",
            INVALID_GRAPH_BINDING_CODE,
        ) from exc
    except Exception as exc:
        raise AdapterRequestError(
            "selected graph binding contract is invalid",
            INVALID_GRAPH_BINDING_CODE,
        ) from exc


def _load_current_graph_contract(
    params: dict[str, Any], authorization: dict[str, Any]
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]], int]:
    workspace = workspace_path(params)
    artifacts_dir = workspace / "artifacts"
    bundles_dir = artifacts_dir / "bundles"
    require_artifact_directory(artifacts_dir, "artifacts directory")
    require_artifact_directory(bundles_dir, "artifact bundles directory")
    current_data = read_artifact_file(
        artifacts_dir / "current.json",
        artifacts_dir,
        "artifact current pointer",
        MAX_ARTIFACT_CURRENT_POINTER_BYTES,
    )
    current = decode_artifact_object(current_data, "artifact current pointer")
    validate_exact_fields(current, CURRENT_POINTER_FIELDS, "artifact current pointer")
    if current.get("version") != 2:
        raise AdapterRequestError("artifact current pointer version must be 2", INVALID_GRAPH_BINDING_CODE)
    projection_id = required_authorization_token(
        current.get("projection_id"), "artifact current pointer.projection_id"
    )
    if not PROJECTION_ID_RE.fullmatch(projection_id) or current.get("projection_version") != projection_id:
        raise AdapterRequestError("artifact current pointer has an invalid projection", INVALID_GRAPH_BINDING_CODE)
    manifest_digest = required_authorization_token(
        current.get("manifest_sha256"), "artifact current pointer.manifest_sha256"
    )
    if not SHA256_RE.fullmatch(manifest_digest):
        raise AdapterRequestError("artifact current pointer has an invalid manifest digest", INVALID_GRAPH_BINDING_CODE)
    bundle_dir = bundles_dir / projection_id
    require_artifact_directory(bundle_dir, "selected artifact bundle")
    manifest_data = read_artifact_file(
        bundle_dir / "manifest.json",
        bundle_dir,
        "artifact bundle manifest",
        MAX_ARTIFACT_BUNDLE_MANIFEST_BYTES,
    )
    if hashlib.sha256(manifest_data).hexdigest() != manifest_digest:
        raise AdapterRequestError("artifact bundle manifest digest does not match current pointer", INVALID_GRAPH_BINDING_CODE)
    manifest = decode_artifact_object(manifest_data, "artifact bundle manifest")
    validate_exact_fields(manifest, BUNDLE_MANIFEST_FIELDS, "artifact bundle manifest")
    if (
        manifest.get("version") != 2
        or manifest.get("projection_id") != projection_id
        or manifest.get("projection_version") != projection_id
        or manifest.get("graph_binding_contract_version")
        not in SUPPORTED_GRAPH_BINDING_CONTRACT_VERSIONS
    ):
        raise AdapterRequestError("artifact bundle has no supported graph binding contract", INVALID_GRAPH_BINDING_CODE)
    required_authorization_token(manifest.get("namespace"), "artifact bundle manifest.namespace")
    authz_object = required_authorization_token(
        manifest.get("authz_object"), "artifact bundle manifest.authz_object"
    )
    if authz_object != "knowledge-base:" + authorization["knowledge_base_id"]:
        raise AdapterRequestError(
            "artifact bundle authorization object is outside the request knowledge base",
            INVALID_GRAPH_BINDING_CODE,
        )
    required_authorization_token(manifest.get("authz_version"), "artifact bundle manifest.authz_version")
    source_snapshot = manifest.get("source_snapshot")
    if not isinstance(source_snapshot, dict):
        raise AdapterRequestError("artifact bundle source_snapshot must be an object", INVALID_GRAPH_BINDING_CODE)
    validate_exact_fields(source_snapshot, SOURCE_SNAPSHOT_FIELDS, "artifact bundle source_snapshot")
    required_authorization_token(source_snapshot.get("version"), "artifact bundle source_snapshot.version")
    digest = required_authorization_token(source_snapshot.get("digest"), "artifact bundle source_snapshot.digest")
    if not SHA256_RE.fullmatch(digest):
        raise AdapterRequestError("artifact bundle source_snapshot.digest is invalid", INVALID_GRAPH_BINDING_CODE)
    document_count = source_snapshot.get("document_count")
    if isinstance(document_count, bool) or not isinstance(document_count, int) or document_count < 1:
        raise AdapterRequestError(
            "artifact bundle source_snapshot.document_count must be positive",
            INVALID_GRAPH_BINDING_CODE,
        )
    files = manifest.get("files")
    if not isinstance(files, list):
        raise AdapterRequestError("artifact bundle files must be a list", INVALID_GRAPH_BINDING_CODE)
    descriptors: dict[str, dict[str, Any]] = {}
    ordered_paths: list[str] = []
    for index, value in enumerate(files):
        descriptor = validate_artifact_descriptor(value, f"artifact bundle files[{index}]")
        path = descriptor["path"]
        if path in descriptors:
            raise AdapterRequestError(f"artifact bundle file {path} is duplicated", INVALID_GRAPH_BINDING_CODE)
        descriptors[path] = descriptor
        ordered_paths.append(path)
    if ordered_paths != sorted(ordered_paths):
        raise AdapterRequestError("artifact bundle files must be sorted by path", INVALID_GRAPH_BINDING_CODE)
    for required_path in (GRAPH_BINDINGS_ARTIFACT, CLAIM_BINDINGS_ARTIFACT):
        if required_path not in descriptors:
            raise AdapterRequestError(
                f"artifact bundle is missing {required_path}", INVALID_GRAPH_BINDING_CODE
            )
    graph_rows = verified_jsonl_rows(
        bundle_dir, descriptors[GRAPH_BINDINGS_ARTIFACT], GRAPH_BINDINGS_ARTIFACT
    )
    if not graph_rows:
        raise AdapterRequestError("graph_bindings.jsonl is empty", INVALID_GRAPH_BINDING_CODE)
    resources: dict[str, dict[str, Any]] = {}
    seen_resource_ids: set[str] = set()
    previous = ""
    for index, row in enumerate(graph_rows):
        binding = validate_graph_binding_row(
            row, f"graph_bindings[{index}]", authorization, manifest
        )
        graph_object_id = binding["graph_object_id"]
        resource_id = binding["resource"]["resource_id"]
        if graph_object_id <= previous or resource_id in seen_resource_ids:
            raise AdapterRequestError(
                "graph_bindings must have unique sorted graph and resource identities",
                INVALID_GRAPH_BINDING_CODE,
            )
        previous = graph_object_id
        seen_resource_ids.add(resource_id)
        resources[graph_object_id] = binding["resource"]
    resources_by_id = {
        resource["resource_id"]: resource for resource in resources.values()
    }
    for resource in resources.values():
        if resource["type"] != "chunk":
            continue
        parent = resources_by_id.get(resource["authorization_resource_id"])
        if (
            parent is None
            or parent["type"] != "document"
            or parent["authz_object"] != resource["authz_object"]
        ):
            raise AdapterRequestError(
                f"chunk {resource['resource_id']} has no exact graph-bound authorization document",
                INVALID_GRAPH_BINDING_CODE,
            )
    claim_rows = verified_jsonl_rows(
        bundle_dir, descriptors[CLAIM_BINDINGS_ARTIFACT], CLAIM_BINDINGS_ARTIFACT
    )
    claims = validate_claim_binding_rows(
        claim_rows, resources, manifest["graph_binding_contract_version"]
    )
    return resources, claims, manifest["graph_binding_contract_version"]


def bounded_primitive_text(value: Any, field: str) -> str:
    text = required_content(value, field)
    if len(text.encode("utf-8")) > MAX_PRIMITIVE_TEXT_BYTES:
        raise AdapterRequestError(f"{field} exceeds the primitive text limit")
    return text


def selected_resource_maps(
    resources: dict[str, dict[str, Any]],
) -> tuple[dict[str, str], dict[str, dict[str, Any]]]:
    graph_by_resource_id: dict[str, str] = {}
    resource_by_id: dict[str, dict[str, Any]] = {}
    for graph_object_id, resource in resources.items():
        resource_id = resource["resource_id"]
        graph_by_resource_id[resource_id] = graph_object_id
        resource_by_id[resource_id] = resource
    return graph_by_resource_id, resource_by_id


def require_selected_resource(
    resource: dict[str, Any],
    resources: dict[str, dict[str, Any]],
    field: str,
) -> str:
    graph_by_resource_id, resource_by_id = selected_resource_maps(resources)
    resource_id = resource["resource_id"]
    selected = resource_by_id.get(resource_id)
    if selected is None or selected != resource:
        raise AdapterRequestError(
            f"{field} does not match the exact selected graph resource binding",
            INVALID_GRAPH_BINDING_CODE,
        )
    return graph_by_resource_id[resource_id]


def permissioned_provider_context(
    params: dict[str, Any],
    authorization: dict[str, Any],
    projection_version: str,
    allowed_graph_object_ids: list[str] | None = None,
) -> dict[str, Any]:
    context = {
        "version": 1,
        "workspace": str(workspace_path(params).resolve()),
        "tenant_id": authorization["tenant_id"],
        "knowledge_base_id": authorization["knowledge_base_id"],
        "projection_version": projection_version,
        "host": str(params.get("host") or "").strip(),
        "config_path": str(params.get("config_path") or "").strip(),
        "project_id": str(params.get("project_id") or "").strip(),
        "namespace": str(params.get("namespace") or "").strip(),
        "language": str(params.get("language") or "").strip(),
    }
    if allowed_graph_object_ids is not None:
        context["allowed_graph_object_ids"] = list(allowed_graph_object_ids)
    return context


def write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("provider runner response write failed")
        view = view[written:]


def deny_provider_parent_fd_access() -> None:
    """Prevent Linux provider children from reopening adapter descriptors via procfs."""
    if not sys.platform.startswith("linux"):
        return
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
        prctl.restype = ctypes.c_int
        if prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_DUMPABLE) failed")
        if prctl(3, 0, 0, 0, 0) != 0:  # PR_GET_DUMPABLE
            raise OSError("adapter process remained dumpable")
    except BaseException as exc:
        raise AdapterRequestError(
            "permissioned primitive provider isolation failed",
            PRIMITIVE_UNAVAILABLE_CODE,
        ) from exc


def enable_linux_provider_subreaper() -> None:
    """Keep daemonized provider descendants attached to the runner."""
    if not sys.platform.startswith("linux"):
        return

    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.restype = ctypes.c_int
    if prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_CHILD_SUBREAPER) failed")
    enabled = ctypes.c_int()
    if prctl(37, ctypes.byref(enabled), 0, 0, 0) != 0:  # PR_GET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "prctl(PR_GET_CHILD_SUBREAPER) failed")
    if enabled.value != 1:
        raise OSError("provider runner did not become a child subreaper")


def posix_process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return False
    return True


def posix_process_parents() -> dict[int, int]:
    """Return a best-effort snapshot of the POSIX process parent graph."""
    parents: dict[int, int] = {}
    if sys.platform.startswith("linux"):
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                stat = (entry / "stat").read_text(encoding="ascii")
                fields = stat[stat.rfind(")") + 2 :].split()
                parents[int(entry.name)] = int(fields[1])
            except (IndexError, OSError, ValueError):
                continue
        return parents

    completed = subprocess.run(
        ["/bin/ps", "-axo", "pid=,ppid="],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="ascii",
        errors="strict",
        timeout=1,
        check=False,
        close_fds=True,
    )
    if completed.returncode != 0:
        raise OSError("provider process tree inspection failed")
    for line in completed.stdout.splitlines():
        fields = line.split()
        if len(fields) != 2:
            continue
        try:
            parents[int(fields[0])] = int(fields[1])
        except ValueError:
            continue
    return parents


def posix_descendant_pids(root_pid: int) -> set[int]:
    parents = posix_process_parents()
    descendants: set[int] = set()
    changed = True
    while changed:
        changed = False
        for pid, parent_pid in parents.items():
            if pid in descendants or pid == root_pid:
                continue
            if parent_pid == root_pid or parent_pid in descendants:
                descendants.add(pid)
                changed = True
    return descendants


def kill_posix_pids(pids: set[int], exclude: set[int] | None = None) -> None:
    excluded = exclude or set()
    for pid in sorted(pids - excluded, reverse=True):
        try:
            os.kill(pid, signal.SIGKILL)
        except (PermissionError, ProcessLookupError):
            pass


def terminate_posix_descendants(
    root_pid: int,
    tracked: set[int] | None = None,
    exclude: set[int] | None = None,
) -> set[int]:
    """Kill detached and ordinary descendants while the root still anchors them."""
    observed = set(tracked or ())
    excluded = exclude or set()
    for _ in range(3):
        try:
            observed.update(posix_descendant_pids(root_pid))
        except OSError:
            pass
        observed.difference_update(excluded)
        kill_posix_pids(observed, excluded)
        time.sleep(0.01)
    return observed


def windows_provider_guardian(parent_pid: int, runner_pid: int) -> int:
    import ctypes

    synchronize = 0x00100000
    process_terminate = 0x0001
    wait_object_0 = 0
    wait_timeout = 258
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel32.WaitForSingleObject.restype = ctypes.c_uint32
    kernel32.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel32.TerminateProcess.restype = ctypes.c_bool
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_bool

    parent = kernel32.OpenProcess(synchronize, False, parent_pid)
    runner = kernel32.OpenProcess(synchronize | process_terminate, False, runner_pid)
    if not parent or not runner:
        if parent:
            kernel32.CloseHandle(parent)
        if runner:
            kernel32.CloseHandle(runner)
        return 1
    try:
        sys.stdout.write("ready\n")
        sys.stdout.flush()
        sys.stdout.close()
        while True:
            parent_status = kernel32.WaitForSingleObject(parent, 20)
            if parent_status == wait_object_0:
                kernel32.TerminateProcess(runner, 1)
                return 0
            if parent_status != wait_timeout:
                return 1
            runner_status = kernel32.WaitForSingleObject(runner, 0)
            if runner_status == wait_object_0:
                return 0
            if runner_status != wait_timeout:
                return 1
    finally:
        kernel32.CloseHandle(parent)
        kernel32.CloseHandle(runner)


def create_windows_provider_job() -> int | None:
    """Bind the runner and descendants to a kill-on-runner-exit Windows job."""
    if os.name != "nt":
        return None

    import ctypes
    from ctypes import wintypes

    class JobObjectBasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IOCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class JobObjectExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JobObjectBasicLimitInformation),
            ("IoInfo", IOCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    job_object_extended_limit_information = 9
    job_object_limit_kill_on_job_close = 0x00002000
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
    limits = JobObjectExtendedLimitInformation()
    limits.BasicLimitInformation.LimitFlags = job_object_limit_kill_on_job_close
    if not kernel32.SetInformationJobObject(
        job,
        job_object_extended_limit_information,
        ctypes.byref(limits),
        ctypes.sizeof(limits),
    ):
        error_code = ctypes.get_last_error()
        kernel32.CloseHandle(job)
        raise OSError(error_code, "SetInformationJobObject failed")
    if not kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess()):
        error_code = ctypes.get_last_error()
        kernel32.CloseHandle(job)
        raise OSError(error_code, "AssignProcessToJobObject failed")
    return int(job)


def permissioned_provider_guardian(parent_pid: int, runner_pid: int, liveness_fd: int) -> int:
    """Terminate the provider process domain if its adapter parent disappears."""
    if parent_pid <= 1 or runner_pid <= 1:
        return 1
    if os.name == "nt":
        return windows_provider_guardian(parent_pid, runner_pid)
    if not posix_process_exists(parent_pid) or not posix_process_exists(runner_pid):
        return 1
    sys.stdout.write("ready\n")
    sys.stdout.flush()
    sys.stdout.close()
    tracked: set[int] = set()
    while posix_process_exists(runner_pid):
        try:
            tracked.update(posix_descendant_pids(runner_pid))
        except OSError:
            pass
        tracked.discard(os.getpid())
        parent_disappeared = not posix_process_exists(parent_pid)
        if liveness_fd >= 0:
            readable, _, _ = select.select([liveness_fd], [], [], 0.02)
            if readable and os.read(liveness_fd, 1) == b"":
                parent_disappeared = True
        elif not parent_disappeared:
            time.sleep(0.02)
        if parent_disappeared:
            try:
                os.kill(runner_pid, signal.SIGSTOP)
            except ProcessLookupError:
                pass
            tracked = terminate_posix_descendants(
                runner_pid,
                tracked,
                exclude={os.getpid()},
            )
            try:
                os.kill(runner_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            kill_posix_pids(tracked, exclude={os.getpid()})
            return 0
    kill_posix_pids(tracked, exclude={os.getpid()})
    return 0


def start_provider_guardian(liveness_fd: int) -> subprocess.Popen[str]:
    options: dict[str, Any] = {}
    if os.name != "nt" and liveness_fd >= 0:
        options["pass_fds"] = (liveness_fd,)
    guardian = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            PERMISSIONED_PROVIDER_GUARDIAN_ARG,
            str(os.getppid()),
            str(os.getpid()),
            str(liveness_fd),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        close_fds=True,
        **options,
    )
    try:
        ready = guardian.stdout.readline() if guardian.stdout is not None else ""
    finally:
        if guardian.stdout is not None:
            guardian.stdout.close()
    if ready != "ready\n" or guardian.poll() is not None:
        try:
            guardian.kill()
        except OSError:
            pass
        guardian.wait()
        raise OSError("provider guardian failed to start")
    return guardian


def permissioned_provider_runner(response_path: str, liveness_fd: int) -> int:
    """Run provider code without inheriting the adapter's output descriptors."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        response_fd = os.open(response_path, flags, 0o600)
    except OSError:
        return 1

    try:
        enable_linux_provider_subreaper()
        _provider_job = create_windows_provider_job()
        _guardian = start_provider_guardian(liveness_fd)
    except BaseException:
        if liveness_fd >= 0:
            os.close(liveness_fd)
        os.close(response_fd)
        return 1
    if liveness_fd >= 0:
        os.close(liveness_fd)

    envelope: dict[str, Any] = {"version": 1, "status": "unavailable"}
    try:
        payload = json.loads(sys.stdin.buffer.read())
        if not isinstance(payload, dict) or set(payload) != {
            "version",
            "provider",
            "context",
            "method",
            "request",
        }:
            raise ValueError("invalid provider runner request")
        spec = payload.get("provider")
        context = payload.get("context")
        method = payload.get("method")
        request = payload.get("request")
        if (
            payload.get("version") != 1
            or not isinstance(spec, str)
            or not PROVIDER_SPEC_RE.fullmatch(spec)
            or not isinstance(context, dict)
            or method not in {"retrieve", "generate"}
            or not isinstance(request, dict)
        ):
            raise ValueError("invalid provider runner request")
        module_name, factory_name = spec.split(":", 1)
        module = importlib.import_module(module_name)
        factory = getattr(module, factory_name)
        provider = factory(dict(context))
        operation = getattr(provider, method, None)
        if not callable(operation):
            raise ValueError("provider capability unavailable")
        provider_response = operation(deepcopy(request))
    except BaseException:
        pass
    else:
        try:
            if not isinstance(provider_response, dict):
                raise TypeError("provider response must be an object")
            normalized_payload = json.dumps(
                provider_response,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
            if len(normalized_payload) > MAX_PROVIDER_RESPONSE_BYTES:
                raise ValueError("provider response exceeds limit")
            normalized_response = json.loads(normalized_payload)
            if type(normalized_response) is not dict:
                raise TypeError("provider response must be a plain object")
        except BaseException:
            envelope = {"version": 1, "status": "invalid_response"}
        else:
            envelope = {
                "version": 1,
                "status": "ok",
                "response": normalized_response,
            }

    if os.name != "nt":
        terminate_posix_descendants(os.getpid(), exclude={_guardian.pid})

    try:
        encoded = json.dumps(
            envelope,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        os.ftruncate(response_fd, 0)
        os.lseek(response_fd, 0, os.SEEK_SET)
        write_all(response_fd, encoded)
        os.fsync(response_fd)
    except BaseException:
        return 1
    finally:
        try:
            os.close(response_fd)
        except OSError:
            pass
    return 0


def terminate_provider_process_domain(process: subprocess.Popen[str]) -> None:
    """Kill and reap the runner plus every descendant in its execution domain."""
    if os.name == "nt":
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
    else:
        try:
            os.kill(process.pid, signal.SIGSTOP)
        except ProcessLookupError:
            pass
        tracked = terminate_posix_descendants(process.pid)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            if process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass
        kill_posix_pids(tracked)
    try:
        process.wait()
    except OSError:
        pass


def call_permissioned_provider(
    context: dict[str, Any], method: str, request: dict[str, Any]
) -> dict[str, Any]:
    spec = os.environ.get(PERMISSIONED_PROVIDER_ENV, "").strip()
    if not PROVIDER_SPEC_RE.fullmatch(spec):
        raise AdapterRequestError(
            "permissioned primitive provider is unavailable",
            PRIMITIVE_UNAVAILABLE_CODE,
        )
    payload = json.dumps(
        {
            "version": 1,
            "provider": spec,
            "context": context,
            "method": method,
            "request": request,
        },
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    )
    deny_provider_parent_fd_access()
    with tempfile.TemporaryDirectory(prefix="knote-kag-provider-") as directory:
        response_path = Path(directory) / "response.json"
        process: subprocess.Popen[str] | None = None
        liveness_read = -1
        liveness_write = -1
        try:
            options: dict[str, Any] = {}
            if os.name != "nt":
                liveness_read, liveness_write = os.pipe()
                options["pass_fds"] = (liveness_read,)
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    PERMISSIONED_PROVIDER_RUNNER_ARG,
                    str(response_path),
                    str(liveness_read),
                ],
                stdin=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=os.name != "nt",
                **options,
            )
            if liveness_read >= 0:
                os.close(liveness_read)
                liveness_read = -1
            process.communicate(payload, timeout=PROVIDER_RUNNER_TIMEOUT_SECONDS)
        except (OSError, subprocess.TimeoutExpired) as exc:
            if process is not None:
                terminate_provider_process_domain(process)
            raise AdapterRequestError(
                "permissioned primitive provider call failed",
                PRIMITIVE_UNAVAILABLE_CODE,
            ) from exc
        finally:
            if liveness_read >= 0:
                os.close(liveness_read)
            if liveness_write >= 0:
                os.close(liveness_write)
            if process is not None and process.poll() is not None:
                terminate_provider_process_domain(process)
        if process.returncode != 0 or not response_path.is_file():
            raise AdapterRequestError(
                "permissioned primitive provider call failed",
                PRIMITIVE_UNAVAILABLE_CODE,
            )
        try:
            read_flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                read_flags |= os.O_NOFOLLOW
            response_fd = os.open(response_path, read_flags)
            with os.fdopen(response_fd, "rb") as stream:
                encoded = stream.read(MAX_PROVIDER_RESPONSE_BYTES + 1025)
            if len(encoded) > MAX_PROVIDER_RESPONSE_BYTES + 1024:
                raise ValueError("provider runner response exceeds limit")
            envelope = json.loads(encoded)
        except (OSError, ValueError, UnicodeError) as exc:
            raise AdapterRequestError(
                "permissioned primitive provider returned an invalid response",
                INVALID_PRIMITIVE_RESPONSE_CODE,
            ) from exc

    if not isinstance(envelope, dict) or envelope.get("version") != 1:
        raise AdapterRequestError(
            "permissioned primitive provider returned an invalid response",
            INVALID_PRIMITIVE_RESPONSE_CODE,
        )
    status = envelope.get("status")
    if status == "unavailable" and set(envelope) == {"version", "status"}:
        raise AdapterRequestError(
            "permissioned primitive provider call failed",
            PRIMITIVE_UNAVAILABLE_CODE,
        )
    if status == "invalid_response" and set(envelope) == {"version", "status"}:
        raise AdapterRequestError(
            "permissioned primitive provider returned an invalid response",
            INVALID_PRIMITIVE_RESPONSE_CODE,
        )
    response = envelope.get("response")
    if (
        status != "ok"
        or set(envelope) != {"version", "status", "response"}
        or type(response) is not dict
    ):
        raise AdapterRequestError(
            "permissioned primitive provider returned an invalid response",
            INVALID_PRIMITIVE_RESPONSE_CODE,
        )
    return response


def validate_discover_request(
    params: dict[str, Any], authorization: dict[str, Any]
) -> tuple[list[str], int]:
    validate_allowed_fields(
        params,
        frozenset({"authorization", "resource_types", "limit"}),
        PRIMITIVE_TRANSPORT_FIELDS,
        "discover params",
    )
    resource_types = validate_sorted_unique_strings(
        params.get("resource_types"),
        "resource_types",
        minimum=1,
        maximum=len(RESOURCE_TYPES),
    )
    for index, resource_type in enumerate(resource_types):
        if resource_type not in RESOURCE_TYPES:
            raise AdapterRequestError(f"resource_types[{index}] is unsupported")
    return resource_types, full_discovery_scan_limit(params)


def discover_resources(
    params: dict[str, Any],
    authorization: dict[str, Any],
    resources: dict[str, dict[str, Any]],
    mode: str,
) -> dict[str, Any]:
    resource_types, limit = validate_discover_request(params, authorization)
    selected = sorted(
        (
            deepcopy(resource)
            for resource in resources.values()
            if resource["type"] in resource_types
        ),
        key=lambda resource: resource["resource_id"],
    )
    for index, resource in enumerate(selected):
        require_authorization_scope(resource, authorization, f"resources[{index}]")
    complete = len(selected) <= limit
    selected = selected[:limit]
    return add_test_stage_spy(
        {"mode": mode, "resources": selected, "complete": complete},
        [("discover.output", [resource["resource_id"] for resource in selected])],
    )


def validate_retrieve_request(
    params: dict[str, Any],
    authorization: dict[str, Any],
    *,
    require_resource: Any,
) -> tuple[str, int, list[tuple[dict[str, Any], Any]]]:
    validate_allowed_fields(
        params,
        frozenset({"authorization", "query", "allowed_resources", "limit"}),
        PRIMITIVE_TRANSPORT_FIELDS,
        "retrieve params",
    )
    query = bounded_primitive_text(params.get("query"), "query").strip()
    limit = primitive_limit(params, 10)
    if not query:
        raise AdapterRequestError("query must be a non-empty string")
    values = params.get("allowed_resources")
    if not isinstance(values, list) or not 1 <= len(values) <= MAX_PRIMITIVE_ITEMS:
        raise AdapterRequestError(
            f"allowed_resources must contain between 1 and {MAX_PRIMITIVE_ITEMS} handles"
        )
    allowed: list[tuple[dict[str, Any], Any]] = []
    projection = ""
    previous_resource_id = ""
    for index, value in enumerate(values):
        field = f"allowed_resources[{index}]"
        resource = validate_resource(value, field)
        require_authorization_scope(resource, authorization, field)
        binding = require_resource(resource, field)
        resource_id = resource["resource_id"]
        if previous_resource_id and resource_id <= previous_resource_id:
            raise AdapterRequestError(
                "allowed_resources must be strictly sorted and unique"
            )
        previous_resource_id = resource_id
        resource_projection = resource["versions"]["projection"]
        if not projection:
            projection = resource_projection
        elif resource_projection != projection:
            raise AdapterRequestError(
                f"{field}.versions.projection does not match the allowed resource set"
            )
        allowed.append((resource, binding))
    return query, limit, allowed


def real_discover(
    params: dict[str, Any],
    authorization: dict[str, Any],
    resources: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    return discover_resources(params, authorization, resources, "real")


def real_retrieve(
    params: dict[str, Any],
    authorization: dict[str, Any],
    resources: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    query, limit, allowed = validate_retrieve_request(
        params,
        authorization,
        require_resource=lambda resource, field: require_selected_resource(
            resource, resources, field
        ),
    )
    projection_version = allowed[0][0]["versions"]["projection"]
    allowed_graph_object_ids = sorted(binding for _resource, binding in allowed)
    allowed_graph_object_id_set = set(allowed_graph_object_ids)
    response = call_permissioned_provider(
        permissioned_provider_context(
            params,
            authorization,
            projection_version,
            allowed_graph_object_ids,
        ),
        "retrieve",
        {
            "version": 1,
            "query": query,
            "limit": limit,
            "projection_version": projection_version,
            "allowed_graph_object_ids": allowed_graph_object_ids,
        },
    )
    try:
        validate_exact_fields(response, frozenset({"candidates"}), "provider retrieve response")
        values = response.get("candidates")
        if not isinstance(values, list) or len(values) > limit:
            raise AdapterRequestError("invalid provider retrieve candidate set")
    except AdapterRequestError as exc:
        raise AdapterRequestError(
            "permissioned retrieve provider returned an invalid candidate set",
            INVALID_PRIMITIVE_RESPONSE_CODE,
        ) from exc
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, value in enumerate(values):
        field = f"provider retrieve response.candidates[{index}]"
        if not isinstance(value, dict):
            raise AdapterRequestError(
                "permissioned retrieve provider returned an invalid candidate",
                INVALID_PRIMITIVE_RESPONSE_CODE,
            )
        try:
            validate_exact_fields(value, frozenset({"graph_object_id", "score"}), field)
            graph_object_id = required_authorization_token(
                value.get("graph_object_id"), f"{field}.graph_object_id"
            )
        except AdapterRequestError as exc:
            raise AdapterRequestError(
                "permissioned retrieve provider returned an invalid candidate",
                INVALID_PRIMITIVE_RESPONSE_CODE,
            ) from exc
        score = value.get("score")
        if (
            graph_object_id not in resources
            or graph_object_id not in allowed_graph_object_id_set
            or graph_object_id in seen
            or isinstance(score, bool)
            or not isinstance(score, (int, float))
            or score < 0
            or score > 1
            or not math.isfinite(score)
        ):
            raise AdapterRequestError(
                "permissioned retrieve provider returned an invalid candidate",
                INVALID_PRIMITIVE_RESPONSE_CODE,
            )
        seen.add(graph_object_id)
        candidates.append({"resource": resources[graph_object_id], "score": float(score)})
    candidates.sort(key=lambda candidate: (-candidate["score"], candidate["resource"]["resource_id"]))
    resource_ids = [candidate["resource"]["resource_id"] for candidate in candidates]
    return add_test_stage_spy(
        {"mode": "real", "candidates": candidates},
        [("retrieve.output", resource_ids)],
    )


def validate_expand_frontier(
    params: dict[str, Any],
    authorization: dict[str, Any],
    operation: dict[str, Any],
    phase: str,
    *,
    require_resource: Any,
) -> tuple[list[dict[str, Any]], int]:
    frontier = params.get("frontier")
    max_frontier = operation["parameters"]["limits"]["max_frontier_width"]
    if (
        not isinstance(frontier, list)
        or not frontier
        or len(frontier) > max_frontier
    ):
        raise AdapterRequestError("frontier must contain between 1 and 100 candidate handles")
    handles: list[dict[str, Any]] = []
    seen: set[str] = set()
    expected_type = "entity" if phase == "entity_to_claim" else "claim"
    projection_version = operation["parameters"]["projection_version"]
    for index, value in enumerate(frontier):
        handle = validate_candidate(value, f"frontier[{index}]")
        require_authorization_scope(handle["resource"], authorization, f"frontier[{index}].resource")
        require_resource(handle["resource"], f"frontier[{index}].resource")
        resource_id = handle["resource"]["resource_id"]
        if resource_id in seen:
            raise AdapterRequestError("frontier contains duplicate resource_id values")
        if handle["resource"]["versions"]["projection"] != projection_version:
            raise AdapterRequestError(
                f"frontier[{index}].resource does not match the operation projection"
            )
        if handle["resource"]["type"] != expected_type:
            raise AdapterRequestError(
                f"frontier[{index}].resource type is unsupported for phase"
            )
        seen.add(resource_id)
        handles.append(handle)
    ordered = sorted(
        handles,
        key=lambda handle: (-handle["score"], handle["resource"]["resource_id"]),
    )
    if handles != ordered:
        raise AdapterRequestError("frontier candidate handles are not deterministically sorted")
    limit = full_expansion_scan_limit(params)
    return handles, limit


def stable_claim_row(
    claim: dict[str, Any], resources: dict[str, dict[str, Any]]
) -> dict[str, str]:
    return {
        "claim_resource_id": resources[claim["claim"]]["resource_id"],
        "subject_resource_id": claim["subject_resource_id"],
        "predicate_key": claim["predicate_key"],
        "object_resource_id": claim["object_resource_id"],
        "source_document_resource_id": claim["source_document_resource_id"],
        "derivation": claim["derivation"],
    }


def claim_matches_filters(
    claim: dict[str, str], filters: list[dict[str, Any]]
) -> bool:
    values = {
        "claim_id_in": claim["claim_resource_id"],
        "object_id_in": claim["object_resource_id"],
        "source_document_id_in": claim["source_document_resource_id"],
        "subject_id_in": claim["subject_resource_id"],
    }
    for item in filters:
        kind = item["kind"]
        if kind == "derivation_in":
            if claim["derivation"] not in item["derivations"]:
                return False
        elif values[kind] not in item["resource_ids"]:
            return False
    return True


def compare_claim_rows(
    left: dict[str, str],
    right: dict[str, str],
    order: list[dict[str, Any]],
) -> int:
    fields = {
        "claim_id": "claim_resource_id",
        "object_id": "object_resource_id",
        "predicate_key": "predicate_key",
        "source_document_id": "source_document_resource_id",
        "subject_id": "subject_resource_id",
    }
    for item in order:
        field = fields[item["key"]]
        if left[field] == right[field]:
            continue
        comparison = -1 if left[field] < right[field] else 1
        if item["direction"] == "descending":
            comparison = -comparison
        return comparison
    return 0


def phase_expansion(
    handles: list[dict[str, Any]],
    limit: int,
    operation: dict[str, Any],
    phase: str,
    resources_by_id: dict[str, dict[str, Any]],
    claims: list[dict[str, str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if limit != MAX_PRIMITIVE_ITEMS:
        raise AdapterRequestError(
            f"limit must equal the full expansion scan limit of {MAX_PRIMITIVE_ITEMS}"
        )
    plan = operation["parameters"]
    frontier_scores = {
        handle["resource"]["resource_id"]: handle["score"] for handle in handles
    }
    matching: list[dict[str, str]] = []
    for claim in claims:
        if claim["predicate_key"] not in plan["predicate_keys"]:
            continue
        if not claim_matches_filters(claim, plan["filters"]):
            continue
        object_resource = resources_by_id.get(claim["object_resource_id"])
        claim_resource = resources_by_id.get(claim["claim_resource_id"])
        if object_resource is None or claim_resource is None:
            raise AdapterRequestError(
                "selected source-backed Claim binding is incomplete",
                INVALID_GRAPH_BINDING_CODE,
            )
        if claim_resource["type"] != "claim" or object_resource["type"] != "entity":
            raise AdapterRequestError(
                "selected source-backed Claim binding has an unsupported edge shape",
                INVALID_GRAPH_BINDING_CODE,
            )
        if phase == "entity_to_claim":
            if claim["subject_resource_id"] not in frontier_scores:
                continue
            if not ({"claim", object_resource["type"]} & set(plan["resource_kinds"])):
                continue
        else:
            if claim["claim_resource_id"] not in frontier_scores:
                continue
            if object_resource["type"] not in plan["resource_kinds"]:
                continue
        matching.append(claim)
    matching.sort(
        key=cmp_to_key(
            lambda left, right: compare_claim_rows(left, right, plan["order"])
        )
    )

    selected_target_ids: list[str] = []
    seen_targets: set[str] = set()
    for claim in matching:
        target_id = (
            claim["claim_resource_id"]
            if phase == "entity_to_claim"
            else claim["object_resource_id"]
        )
        if target_id in seen_targets:
            continue
        if len(selected_target_ids) == limit:
            raise AdapterRequestError(
                "expansion candidate limit exceeded",
                INVALID_PRIMITIVE_RESPONSE_CODE,
            )
        seen_targets.add(target_id)
        selected_target_ids.append(target_id)
    selected_targets = set(selected_target_ids)
    candidate_scores: dict[str, float] = {}
    expansions: list[dict[str, Any]] = []
    for claim in matching:
        target_id = (
            claim["claim_resource_id"]
            if phase == "entity_to_claim"
            else claim["object_resource_id"]
        )
        if target_id not in selected_targets:
            continue
        source_id = (
            claim["subject_resource_id"]
            if phase == "entity_to_claim"
            else claim["claim_resource_id"]
        )
        score = float(frontier_scores[source_id])
        candidate_scores[target_id] = max(candidate_scores.get(target_id, 0.0), score)
        expansions.append(
            {
                "from_resource_id": source_id,
                "to_resource_id": target_id,
                "claim_resource_id": claim["claim_resource_id"],
                "predicate_key": claim["predicate_key"],
                "hop": 1,
            }
        )
    candidates = [
        {"resource": resources_by_id[resource_id], "score": score}
        for resource_id, score in candidate_scores.items()
    ]
    candidates.sort(
        key=lambda candidate: (-candidate["score"], candidate["resource"]["resource_id"])
    )
    expansions.sort(
        key=lambda edge: (
            edge["hop"],
            edge["from_resource_id"],
            edge["to_resource_id"],
            edge["claim_resource_id"],
            edge["predicate_key"],
        )
    )
    return candidates, expansions


def real_expand(
    params: dict[str, Any],
    authorization: dict[str, Any],
    resources: dict[str, dict[str, Any]],
    claims: list[dict[str, Any]],
    identity_version: int,
    operation: dict[str, Any],
    phase: str,
) -> dict[str, Any]:
    projection_version = next(iter(resources.values()))["versions"]["projection"]
    operation = validate_graph_operation(
        operation,
        expected_projection=projection_version,
        expected_identity_version=identity_version,
    )
    resources_by_id = {
        resource["resource_id"]: resource for resource in resources.values()
    }
    handles, limit = validate_expand_frontier(
        params,
        authorization,
        operation,
        phase,
        require_resource=lambda resource, field: require_selected_resource(
            resource, resources, field
        ),
    )
    stable_claims = [stable_claim_row(claim, resources) for claim in claims]
    candidates, expansions = phase_expansion(
        handles,
        limit,
        operation,
        phase,
        resources_by_id,
        stable_claims,
    )
    frontier_ids = [handle["resource"]["resource_id"] for handle in handles]
    output_ids = [candidate["resource"]["resource_id"] for candidate in candidates]
    return add_test_stage_spy(
        {"mode": "real", "candidates": candidates, "expansions": expansions},
        [("expand.frontier_input", frontier_ids), ("expand.candidate_output", output_ids)],
    )


def validate_generate_path_binding(value: Any, field: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise AdapterRequestError(f"{field} must be an object")
    validate_exact_fields(value, GENERATE_PATH_CLAIM_BINDING_FIELDS, field)
    binding = {
        name: required_authorization_token(value.get(name), f"{field}.{name}")
        for name in sorted(GENERATE_PATH_CLAIM_BINDING_FIELDS)
    }
    for name in ("parent_resource_id", "claim_resource_id", "object_resource_id"):
        if not RESOURCE_ID_RE.fullmatch(binding[name]):
            raise AdapterRequestError(f"{field}.{name} must be an opaque res_ identifier")
    if (
        not CLAIM_PREDICATE_KEY_RE.fullmatch(binding["predicate_key"])
        or binding["predicate_key"] not in SUPPORTED_CLAIM_PREDICATE_KEYS
    ):
        raise AdapterRequestError(
            f"{field}.predicate_key is not declared by the active allowlist"
        )
    if len(
        {
            binding["parent_resource_id"],
            binding["claim_resource_id"],
            binding["object_resource_id"],
        }
    ) != 3:
        raise AdapterRequestError(f"{field} resources must be distinct")
    return binding


def validate_generate_paths(
    value: Any,
    evidence: list[dict[str, Any]],
    authorization: dict[str, Any],
    *,
    require_resource: Any,
    claims: list[dict[str, Any]] | tuple[dict[str, Any], ...],
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(evidence):
        raise AdapterRequestError(
            "paths must contain exactly one complete path per evidence item"
        )
    claims_by_id: dict[str, dict[str, Any]] = {}
    for claim in claims:
        claim_resource_id = claim["claim_resource_id"]
        if claim_resource_id in claims_by_id:
            raise AdapterRequestError(
                "selected Claim bindings contain duplicate claim_resource_id values",
                INVALID_GRAPH_BINDING_CODE,
            )
        claims_by_id[claim_resource_id] = claim

    paths: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for path_index, path_value in enumerate(value):
        field = f"paths[{path_index}]"
        if not isinstance(path_value, dict):
            raise AdapterRequestError(f"{field} must be an object")
        validate_exact_fields(path_value, GENERATE_PATH_FIELDS, field)
        resource_values = path_value.get("resources")
        binding_values = path_value.get("claim_bindings")
        if (
            not isinstance(resource_values, list)
            or not resource_values
            or len(resource_values) > MAX_PRIMITIVE_ITEMS
        ):
            raise AdapterRequestError(
                f"{field}.resources must contain between 1 and {MAX_PRIMITIVE_ITEMS} handles"
            )
        if not isinstance(binding_values, list) or len(binding_values) > MAX_PRIMITIVE_ITEMS:
            raise AdapterRequestError(
                f"{field}.claim_bindings must contain at most {MAX_PRIMITIVE_ITEMS} bindings"
            )
        if len(resource_values) != 2 * len(binding_values) + 1:
            raise AdapterRequestError(
                f"{field} must contain complete entity/Claim/entity segments"
            )

        resources: list[dict[str, Any]] = []
        resource_ids: set[str] = set()
        projection_version = evidence[path_index]["resource"]["versions"]["projection"]
        for resource_index, resource_value in enumerate(resource_values):
            resource_field = f"{field}.resources[{resource_index}]"
            resource = validate_resource(resource_value, resource_field)
            require_authorization_scope(resource, authorization, resource_field)
            require_resource(resource, resource_field)
            expected_type = "entity" if resource_index % 2 == 0 else "claim"
            if resource["type"] != expected_type:
                raise AdapterRequestError(
                    f"{resource_field} does not match the entity/Claim/entity path shape"
                )
            if resource["versions"]["projection"] != projection_version:
                raise AdapterRequestError(
                    f"{resource_field} does not match the evidence projection"
                )
            resource_id = resource["resource_id"]
            if resource_id in resource_ids:
                raise AdapterRequestError(f"{field} contains duplicate resource_id values")
            resource_ids.add(resource_id)
            resources.append(resource)

        bindings: list[dict[str, str]] = []
        seen_bindings: set[tuple[str, str, str, str]] = set()
        for binding_index, binding_value in enumerate(binding_values):
            binding_field = f"{field}.claim_bindings[{binding_index}]"
            binding = validate_generate_path_binding(binding_value, binding_field)
            parent = resources[binding_index * 2]
            claim_resource = resources[binding_index * 2 + 1]
            object_resource = resources[binding_index * 2 + 2]
            if (
                binding["parent_resource_id"] != parent["resource_id"]
                or binding["claim_resource_id"] != claim_resource["resource_id"]
                or binding["object_resource_id"] != object_resource["resource_id"]
            ):
                raise AdapterRequestError(
                    f"{binding_field} does not match the resource sequence"
                )
            selected = claims_by_id.get(binding["claim_resource_id"])
            selected_binding = None
            if selected is not None:
                selected_binding = {
                    "parent_resource_id": selected["subject_resource_id"],
                    "claim_resource_id": selected["claim_resource_id"],
                    "object_resource_id": selected["object_resource_id"],
                    "predicate_key": selected["predicate_key"],
                }
            if selected_binding != binding:
                raise AdapterRequestError(
                    f"{binding_field} does not match the exact selected Claim binding",
                    INVALID_GRAPH_BINDING_CODE,
                )
            binding_key = (
                binding["parent_resource_id"],
                binding["claim_resource_id"],
                binding["object_resource_id"],
                binding["predicate_key"],
            )
            if binding_key in seen_bindings:
                raise AdapterRequestError(f"{field} contains duplicate Claim bindings")
            seen_bindings.add(binding_key)
            bindings.append(binding)

        if resources[-1] != evidence[path_index]["resource"]:
            raise AdapterRequestError(
                f"{field} terminal resource does not exactly match the paired evidence"
            )
        path = {"resources": resources, "claim_bindings": bindings}
        path_key = json.dumps(path, sort_keys=True, separators=(",", ":"))
        if path_key in seen_paths:
            raise AdapterRequestError("paths contains duplicate complete paths")
        seen_paths.add(path_key)
        paths.append(path)
    return paths


def validate_real_generate_request(
    params: dict[str, Any],
    authorization: dict[str, Any],
    resources: dict[str, dict[str, Any]],
    claims: list[dict[str, Any]],
) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]] | None]:
    validate_allowed_fields(
        params,
        frozenset({"authorization", "question", "evidence"}),
        PRIMITIVE_TRANSPORT_FIELDS | frozenset({"paths"}),
        "generate params",
    )
    question = bounded_primitive_text(params.get("question"), "question").strip()
    evidence = params.get("evidence")
    if not isinstance(evidence, list) or not evidence or len(evidence) > 100:
        raise AdapterRequestError("evidence must contain between 1 and 100 authorized evidence objects")
    items: list[dict[str, Any]] = []
    resource_ids: set[str] = set()
    citation_handles: set[str] = set()
    projection_version = ""
    for index, value in enumerate(evidence):
        item = validate_evidence(value, f"evidence[{index}]")
        if len(item["content"].encode("utf-8")) > MAX_PRIMITIVE_TEXT_BYTES:
            raise AdapterRequestError(f"evidence[{index}].content exceeds the primitive text limit")
        require_authorization_scope(item["resource"], authorization, f"evidence[{index}].resource")
        require_selected_resource(item["resource"], resources, f"evidence[{index}].resource")
        resource_id = item["resource"]["resource_id"]
        citation_handle = item["citation_handle"]
        if resource_id in resource_ids:
            raise AdapterRequestError("evidence contains duplicate resource_id values")
        if citation_handle in citation_handles:
            raise AdapterRequestError("evidence contains duplicate citation_handle values")
        item_projection = item["resource"]["versions"]["projection"]
        if projection_version and projection_version != item_projection:
            raise AdapterRequestError("evidence crosses selected projection versions")
        projection_version = item_projection
        resource_ids.add(resource_id)
        citation_handles.add(citation_handle)
        items.append(item)
    if not question:
        raise AdapterRequestError("question must be a non-empty string")
    paths = None
    if "paths" in params:
        stable_claims = [stable_claim_row(claim, resources) for claim in claims]
        paths = validate_generate_paths(
            params.get("paths"),
            items,
            authorization,
            require_resource=lambda resource, field: require_selected_resource(
                resource, resources, field
            ),
            claims=stable_claims,
        )
    return question, items, paths


def real_generate(
    params: dict[str, Any],
    authorization: dict[str, Any],
    resources: dict[str, dict[str, Any]],
    claims: list[dict[str, Any]],
) -> dict[str, Any]:
    question, items, paths = validate_real_generate_request(
        params, authorization, resources, claims
    )
    projection_version = items[0]["resource"]["versions"]["projection"]
    provider_request: dict[str, Any] = {
        "version": 1,
        "question": question,
        "projection_version": projection_version,
        "evidence": items,
    }
    if paths is not None:
        provider_request["paths"] = paths
    response = call_permissioned_provider(
        permissioned_provider_context(params, authorization, projection_version),
        "generate",
        provider_request,
    )
    try:
        validate_exact_fields(response, frozenset({"answer"}), "provider generate response")
        answer = bounded_primitive_text(response.get("answer"), "provider generate response.answer")
    except AdapterRequestError as exc:
        raise AdapterRequestError(
            "permissioned generate provider returned an invalid response",
            INVALID_PRIMITIVE_RESPONSE_CODE,
        ) from exc
    resource_ids = [item["resource"]["resource_id"] for item in items]
    citations = [
        {"handle": item["citation_handle"], "resource_id": item["resource"]["resource_id"]}
        for item in items
    ]
    return add_test_stage_spy(
        {
            "mode": "real",
            "answer": answer,
            "citations": citations,
            "evidence_resource_ids": resource_ids,
            "trace": {"resource_ids": resource_ids, "count": len(resource_ids)},
        },
        generate_stage_spy(resource_ids, paths),
    )


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


def generate_stage_spy(
    evidence_resource_ids: list[str],
    paths: list[dict[str, Any]] | None,
) -> list[tuple[str, list[str]]]:
    stages = [("generate.evidence_input", evidence_resource_ids)]
    if paths is not None:
        stages.extend(
            (
                "generate.path_input",
                [resource["resource_id"] for resource in path["resources"]],
            )
            for path in paths
        )
    stages.append(("generate.citation_output", evidence_resource_ids))
    return stages


def fake_discover(params: dict[str, Any]) -> dict[str, Any]:
    authorization = validate_authorization(params.get("authorization"))
    resources = {
        resource_id: deepcopy(candidate["resource"])
        for resource_id, candidate in FAKE_CANDIDATES_BY_ID.items()
    }
    return discover_resources(params, authorization, resources, "fake")


def fake_retrieve(params: dict[str, Any]) -> dict[str, Any]:
    authorization = validate_authorization(params.get("authorization"))
    _query, limit, allowed = validate_retrieve_request(
        params,
        authorization,
        require_resource=lambda resource, field: require_fake_resource_binding(
            resource, field
        ),
    )
    allowed_resource_ids = {resource["resource_id"] for resource, _binding in allowed}
    maybe_test_primitive_delay()
    retrieved = [
        (copy_fake_candidate(resource_id), FAKE_CONTENT_BY_ID[resource_id])
        for resource_id in FAKE_RETRIEVE_IDS
        if resource_id in allowed_resource_ids
    ]
    retrieved = retrieved[:limit]
    candidates = [candidate for candidate, _protected_content in retrieved]
    for index, candidate in enumerate(candidates):
        require_authorization_scope(
            candidate["resource"], authorization, f"candidates[{index}].resource"
        )
    resource_ids = [candidate["resource"]["resource_id"] for candidate in candidates]
    return add_test_stage_spy(
        {"mode": "fake", "candidates": candidates},
        [("retrieve.output", resource_ids)],
    )


def fake_expand(params: dict[str, Any]) -> dict[str, Any]:
    authorization = validate_authorization(params.get("authorization"))
    operation, phase = validate_expand_contract(
        params,
        expected_projection=FAKE_PROJECTION_VERSION,
        expected_identity_version=GRAPH_BINDING_CONTRACT_VERSION,
    )
    handles, limit = validate_expand_frontier(
        params,
        authorization,
        operation,
        phase,
        require_resource=require_fake_resource_binding,
    )
    maybe_test_primitive_delay()
    resources_by_id = {
        resource_id: deepcopy(candidate["resource"])
        for resource_id, candidate in FAKE_CANDIDATES_BY_ID.items()
    }
    candidates, expansions = phase_expansion(
        handles,
        limit,
        operation,
        phase,
        resources_by_id,
        list(FAKE_CLAIMS),
    )
    for index, candidate in enumerate(candidates):
        require_authorization_scope(
            candidate["resource"], authorization, f"candidates[{index}].resource"
        )
        expected_type = "claim" if phase == "entity_to_claim" else "entity"
        if candidate["resource"]["type"] != expected_type:
            raise AdapterRequestError("fake expansion produced an unsupported edge shape")
    frontier_ids = [handle["resource"]["resource_id"] for handle in handles]
    output_ids = [candidate["resource"]["resource_id"] for candidate in candidates]
    return add_test_stage_spy(
        {"mode": "fake", "candidates": candidates, "expansions": expansions},
        [
            ("expand.frontier_input", frontier_ids),
            ("expand.candidate_output", output_ids),
        ],
    )


def fake_generate(params: dict[str, Any]) -> dict[str, Any]:
    authorization = validate_authorization(params.get("authorization"))
    validate_allowed_fields(
        params,
        frozenset({"authorization", "question", "evidence"}),
        PRIMITIVE_TRANSPORT_FIELDS | frozenset({"paths"}),
        "generate params",
    )
    question = bounded_primitive_text(params.get("question"), "question").strip()
    evidence = params.get("evidence")
    if not isinstance(evidence, list) or not 1 <= len(evidence) <= MAX_PRIMITIVE_ITEMS:
        raise AdapterRequestError(
            "evidence must be a non-empty list of already-authorized evidence objects"
        )
    items = [validate_evidence(value, f"evidence[{index}]") for index, value in enumerate(evidence)]
    for index, item in enumerate(items):
        if len(item["content"].encode("utf-8")) > MAX_PRIMITIVE_TEXT_BYTES:
            raise AdapterRequestError(
                f"evidence[{index}].content exceeds the primitive text limit"
            )
        require_authorization_scope(
            item["resource"], authorization, f"evidence[{index}].resource"
        )
        require_fake_resource_binding(item["resource"], f"evidence[{index}].resource")
    resource_ids = [item["resource"]["resource_id"] for item in items]
    citation_handles = [item["citation_handle"] for item in items]
    if len(resource_ids) != len(set(resource_ids)):
        raise AdapterRequestError("evidence contains duplicate resource_id values")
    if len(citation_handles) != len(set(citation_handles)):
        raise AdapterRequestError("evidence contains duplicate citation_handle values")
    paths = None
    if "paths" in params:
        paths = validate_generate_paths(
            params.get("paths"),
            items,
            authorization,
            require_resource=require_fake_resource_binding,
            claims=FAKE_CLAIMS,
        )
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
        generate_stage_spy(resource_ids, paths),
    )


def fake_response(req: dict[str, Any]) -> None:
    req_id = req.get("id", "")
    method = req.get("method", "")
    if method in PRIMITIVE_METHODS:
        params = primitive_params(req)
        handlers = {
            "kag.discover": fake_discover,
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
    replay = load_replayable_build_receipt(params, out_dir, idempotency_key)
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
        params = primitive_params(req)
        authorization = validate_authorization(params.get("authorization"))
        operation: dict[str, Any] | None = None
        phase = ""
        if method == "kag.expand":
            operation, phase = validate_expand_contract(params)
        resources, claims, identity_version = load_current_graph_contract(
            params, authorization
        )
        handlers = {
            "kag.discover": lambda: real_discover(
                params, authorization, resources
            ),
            "kag.retrieve": lambda: real_retrieve(params, authorization, resources),
            "kag.expand": lambda: real_expand(
                params,
                authorization,
                resources,
                claims,
                identity_version,
                operation or {},
                phase,
            ),
            "kag.generate": lambda: real_generate(
                params, authorization, resources, claims
            ),
        }
        result(req_id, handlers[method]())
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
            out_dir = runtime_dir(params)
            replay = load_replayable_build_receipt(params, out_dir, idempotency_key)
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
    if len(sys.argv) == 4 and sys.argv[1] == PERMISSIONED_PROVIDER_RUNNER_ARG:
        raise SystemExit(permissioned_provider_runner(sys.argv[2], int(sys.argv[3])))
    if len(sys.argv) == 5 and sys.argv[1] == PERMISSIONED_PROVIDER_GUARDIAN_ARG:
        raise SystemExit(
            permissioned_provider_guardian(
                int(sys.argv[2]),
                int(sys.argv[3]),
                int(sys.argv[4]),
            )
        )
    raise SystemExit(main())
