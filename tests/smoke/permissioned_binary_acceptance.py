#!/usr/bin/env python3
"""Deterministic acceptance for the built permissioned knote binary."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import http.server
import json
import math
import os
import re
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from tui_smoke import PTYDriver, latest_session_id


STORE_ID = "01GXSA8YR785C4FYS3C0RTG7B1"
MODEL_ID = "01GAHCE4YVKPQEKZQHT2R89MQV"
PROJECTION_ID = "prj_78000000000000000000000000000002"
GENERATED_AT = "1970-01-01T00:00:00Z"
TENANT_ID = "tenant_permissioned_binary"
KNOWLEDGE_BASE_ID = "kb_permissioned_binary"
SOURCE_VERSION = "source_permissioned_binary_v1"
ACL_VERSION = "acl_permissioned_binary_v1"
IDENTITY_WATERMARK = "identity_permissioned_binary_v1"
SECURITY_DOMAIN = "domain_permissioned_binary"
PREDICATE_SOURCE = "part_of"
SUPPORT_ID = "support_permissioned_binary_v1"

PROTECTED_CONTENT = "PROTECTED_BINARY_CONTENT_CANARY_78"
PROTECTED_CLAIM = "PROTECTED_BINARY_CLAIM_CANARY_78"
PROVIDER_ANSWER = "PROTECTED_PROVIDER_ANSWER_CANARY_78"
AUTHORIZED_TUI_ANSWER = "permissioned-binary-authorized-ok"
EXPLAIN_TUI_ANSWER = "permissioned-binary-explain-ok"
UNBOUND_MODEL_CANARY = "UNBOUND_MODEL_OUTPUT_CANARY_78"
OPENAI_API_KEY = "openai-local-secret-issue-78"
OPENFGA_API_TOKEN = "openfga-local-secret-issue-78"
PROVIDER_FAILURE_SECRET = "provider-local-secret-issue-78"
BACKEND_FAILURE_SECRET = "openfga-backend-secret-issue-78"
PRINCIPAL_ID = "principal_permissioned_binary_canary_78"

QUERY_PROMPT = "Use knote_query to answer the permissioned binary acceptance question."
EXPLAIN_PROMPT = "Use knote_explain to explain the permissioned binary acceptance answer."
FAILURE_MESSAGE = "protected content is unavailable"
TELEMETRY_ENV = "KNOTE_PERMISSIONED_TELEMETRY_PATH"

TELEMETRY_INTEGER_FIELDS = {
    "contract_version",
    "sample_count",
    "candidate_count",
    "allowed_count",
    "dropped_count",
    "retrieve_candidate_count",
    "evidence_item_count",
    "selected_path_count",
    "complete_path_count",
    "unauthorized_path_count",
    "unauthorized_generator_count",
    "batch_check_count",
    "batch_check_rpc_count",
    "final_filter_candidate_count",
    "final_filter_allowed_count",
    "final_filter_dropped_count",
    "reconciliation_add_count",
    "reconciliation_remove_count",
    "elapsed_ms",
    "duration_ms",
    "latency_ms",
    "batch_check_latency_ms",
    "p95_ms",
    "p99_ms",
    "revocation_p95_ms",
    "revocation_p99_ms",
}
TELEMETRY_NUMBER_FIELDS = {
    "recall_at_4",
    "precision_at_4",
    "positive_empty_rate",
    "negative_empty_rate",
    "authorized_path_completeness",
    "hop_authorization_drop_rate",
    "post_filter_drop_rate",
}
TELEMETRY_ENUM_FIELDS = {
    "metric_scope": {"operational", "cohort"},
    "event": {
        "permissioned_query",
        "permissioned_replay",
        "permissioned_reconciliation",
        "permissioned_revocation",
    },
    "stage": {
        "authorization",
        "discover",
        "retrieve",
        "traversal",
        "final_filter",
        "evidence_load",
        "generate",
        "replay",
        "reconciliation",
        "complete",
    },
    "outcome": {
        "ok",
        "allowed",
        "denied",
        "not_found",
        "provider_unavailable",
        "backend_unavailable",
        "budget_exceeded",
        "failed",
    },
    "budget": {
        "local_hard_latency",
        "synthetic_p99",
        "revocation_p95",
        "revocation_p99",
        "batch_check_size",
    },
    "budget_result": {"pass", "fail"},
}
TELEMETRY_ALLOWED_FIELDS = (
    TELEMETRY_INTEGER_FIELDS
    | TELEMETRY_NUMBER_FIELDS
    | set(TELEMETRY_ENUM_FIELDS)
)


class AcceptanceError(Exception):
    def __init__(self, stage: str, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.stage = stage
        self.code = code


def require(condition: bool, stage: str, code: str, detail: str = "") -> None:
    if not condition:
        raise AcceptanceError(stage, code, detail)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def content_digest(text: str) -> str:
    return "sha256:" + sha256_hex(text.encode("utf-8"))


def resource_id(resource_type: str, source_key: str) -> str:
    identity = "\0".join((TENANT_ID, KNOWLEDGE_BASE_ID, resource_type, source_key))
    return "res_" + sha256_hex(identity.encode("utf-8"))[:32]


def graph_object_id(resource: str) -> str:
    identity = f"2\0{PROJECTION_ID}\0{resource}"
    return "kg_" + sha256_hex(identity.encode("utf-8"))[:32]


def opaque_key(prefix: str, source: str) -> str:
    return prefix + sha256_hex(source.encode("utf-8"))[:32]


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def jsonl_bytes(values: list[dict[str, Any]]) -> bytes:
    return b"".join(json_bytes(value) for value in values)


def write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    path.write_bytes(data)
    path.chmod(0o600)


@dataclass(frozen=True)
class FixtureState:
    workspace: Path
    subject_graph_id: str
    resource_ids: tuple[str, ...]
    manifest_digest: str

    @property
    def protected_markers(self) -> tuple[str, ...]:
        return (
            PROTECTED_CONTENT,
            PROTECTED_CLAIM,
            PROVIDER_ANSWER,
            UNBOUND_MODEL_CANARY,
            *self.resource_ids,
        )


@dataclass
class IdentityFixture:
    root: Path
    store_path: Path
    public_key: str
    assertion_paths: tuple[Path, ...]
    identity_watermark: str
    next_assertion: int = 0

    def take_assertion(self) -> Path:
        if self.next_assertion >= len(self.assertion_paths):
            raise AcceptanceError("identity", "assertion_pool_exhausted")
        path = self.assertion_paths[self.next_assertion]
        self.next_assertion += 1
        return path


def run_identity_fixture(root: Path, *arguments: str) -> dict[str, Any]:
    command = [
        "go",
        "run",
        "./tests/fixtures/permissioned-binary/identity_fixture",
        *arguments,
    ]
    completed = subprocess.run(
        command,
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    require(completed.returncode == 0, "identity", "fixture_failed")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise AcceptanceError("identity", "fixture_output_invalid") from exc
    require(isinstance(value, dict), "identity", "fixture_output_invalid")
    return value


def initialize_identity_fixture(root: Path, run_root: Path) -> IdentityFixture:
    fixture_root = (run_root / "identity").resolve()
    value = run_identity_fixture(
        root,
        "--mode=init",
        f"--root={fixture_root}",
        "--count=24",
    )
    store_path = Path(value.get("store_path", ""))
    assertion_paths = tuple(Path(path) for path in value.get("assertion_paths", []))
    public_key = value.get("public_key", "")
    watermark = value.get("identity_watermark", "")
    require(store_path.is_absolute() and store_path.is_dir(), "identity", "store_missing")
    require(len(assertion_paths) == 24, "identity", "assertion_pool_invalid")
    require(all(path.is_absolute() and path.is_file() for path in assertion_paths), "identity", "assertion_missing")
    require(isinstance(public_key, str) and public_key, "identity", "public_key_missing")
    require(isinstance(watermark, str) and watermark, "identity", "watermark_missing")
    return IdentityFixture(
        root=fixture_root,
        store_path=store_path,
        public_key=public_key,
        assertion_paths=assertion_paths,
        identity_watermark=watermark,
    )


def bump_identity_fixture(root: Path, fixture: IdentityFixture) -> str:
    value = run_identity_fixture(
        root,
        "--mode=bump",
        f"--root={fixture.root}",
        "--generation=2",
    )
    watermark = value.get("identity_watermark", "")
    require(isinstance(watermark, str) and watermark, "identity", "watermark_missing")
    require(watermark != fixture.identity_watermark, "identity", "watermark_did_not_advance")
    fixture.identity_watermark = watermark
    return watermark


def _versions(role: str) -> dict[str, str]:
    return {
        "source": SOURCE_VERSION,
        "content": f"content_{role}_v1",
        "acl": ACL_VERSION,
        "index": "index_" + PROJECTION_ID,
        "graph": "graph_" + PROJECTION_ID,
        "projection": PROJECTION_ID,
    }


def _metadata(
    resource: str,
    resource_type: str,
    source_key: str,
    authorization_object: str,
    authorization_resource: str,
    content: str,
    role: str,
    dependencies: list[str] | None = None,
    claim_record: dict[str, Any] | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "resource_id": resource,
        "type": resource_type,
        "scope": {"tenant_id": TENANT_ID, "knowledge_base_id": KNOWLEDGE_BASE_ID},
        "source_key": source_key,
        "authz_object": authorization_object,
        "authorization_resource_id": authorization_resource,
        "content_digest": content_digest(content),
        "versions": _versions(role),
        "serving_state": "serving",
        "projection_status": {
            "content": "succeeded",
            "acl": "succeeded",
            "index": "succeeded",
            "graph": "succeeded",
            "artifacts": "succeeded",
        },
        "sensitivity": "restricted",
        "security_domain": SECURITY_DOMAIN,
    }
    if dependencies:
        value["dependencies"] = sorted(dependencies)
    if claim_record is not None:
        value["claim_record"] = claim_record
    return value


def _serving_handle(metadata: dict[str, Any]) -> dict[str, Any]:
    scope = metadata["scope"]
    return {
        "resource_id": metadata["resource_id"],
        "type": metadata["type"],
        "tenant_id": scope["tenant_id"],
        "knowledge_base_id": scope["knowledge_base_id"],
        "authz_object": metadata["authz_object"],
        "authorization_resource_id": metadata["authorization_resource_id"],
        "content_digest": metadata["content_digest"],
        "versions": metadata["versions"],
        "serving_state": "serving",
    }


def materialize_workspace(workspace: Path) -> FixtureState:
    workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
    workspace.chmod(0o700)

    document_text = "Synthetic source for deterministic permissioned binary acceptance."
    chunk_text = "Synthetic support for the protected permissioned answer."
    subject_text = "Permissioned binary subject"
    target_text = PROTECTED_CONTENT
    claim_text = PROTECTED_CLAIM

    ids = {
        "document": resource_id("document", "document_permissioned_binary"),
        "chunk": resource_id("chunk", "chunk_permissioned_binary"),
        "subject": resource_id("entity", "entity_subject_permissioned_binary"),
        "target": resource_id("entity", "entity_target_permissioned_binary"),
        "claim": resource_id("claim", "claim_permissioned_binary"),
    }
    document_ref = {
        "resource_id": ids["document"],
        "source_version": SOURCE_VERSION,
        "content_version": _versions("document")["content"],
        "acl_version": ACL_VERSION,
        "projection_version": PROJECTION_ID,
    }
    evidence_ref = {
        "resource_id": ids["chunk"],
        "type": "chunk",
        "versions": _versions("chunk"),
        "document": document_ref,
    }
    provenance = {
        "derivation_mode": "any_support",
        "supports": [{"support_id": SUPPORT_ID, "evidence": [evidence_ref], "complete": True}],
    }
    predicate_key = opaque_key("pred_", PREDICATE_SOURCE)
    claim_record = {
        "binding_state": "source_backed",
        "subject_resource_id": ids["subject"],
        "predicate_key": predicate_key,
        "object_resource_id": ids["target"],
        "source_document": document_ref,
        "provenance": provenance,
    }

    document_authz = "document:" + ids["document"]
    resources = [
        _metadata(
            ids["document"], "document", "document_permissioned_binary", document_authz,
            ids["document"], document_text, "document",
        ),
        _metadata(
            ids["chunk"], "chunk", "chunk_permissioned_binary", document_authz,
            ids["document"], chunk_text, "chunk", [ids["document"]],
        ),
        _metadata(
            ids["subject"], "entity", "entity_subject_permissioned_binary",
            "entity:" + ids["subject"], ids["subject"], subject_text, "subject", [ids["chunk"]],
        ),
        _metadata(
            ids["target"], "entity", "entity_target_permissioned_binary",
            "entity:" + ids["target"], ids["target"], target_text, "target", [ids["document"]],
        ),
        _metadata(
            ids["claim"], "claim", "claim_permissioned_binary", "claim:" + ids["claim"],
            ids["claim"], claim_text, "claim",
            [ids["document"], ids["chunk"], ids["subject"], ids["target"]], claim_record,
        ),
    ]
    resources.sort(key=lambda value: value["resource_id"])

    snapshot_digest = sha256_hex(b"permissioned-binary-source-snapshot-v1")
    projection = {
        "scope": {"tenant_id": TENANT_ID, "knowledge_base_id": KNOWLEDGE_BASE_ID},
        "version": PROJECTION_ID,
        "source_snapshot": {
            "scope": {"tenant_id": TENANT_ID, "knowledge_base_id": KNOWLEDGE_BASE_ID},
            "source_id": "source_permissioned_binary",
            "version": SOURCE_VERSION,
            "security_domain": SECURITY_DOMAIN,
            "digest": "sha256:" + snapshot_digest,
            "document_count": 1,
        },
        "state": "serving",
        "resources": resources,
    }

    graph_bindings = []
    graph_ids: dict[str, str] = {}
    for metadata in resources:
        resource = metadata["resource_id"]
        graph_id = graph_object_id(resource)
        graph_ids[resource] = graph_id
        graph_bindings.append(
            {"version": 2, "graph_object_id": graph_id, "resource": _serving_handle(metadata)}
        )
    graph_bindings.sort(key=lambda value: value["graph_object_id"])

    support_key = opaque_key("sup_", SUPPORT_ID)
    claim_binding = {
        "version": 2,
        "claim": graph_ids[ids["claim"]],
        "subject": graph_ids[ids["subject"]],
        "predicate_key": predicate_key,
        "object": graph_ids[ids["target"]],
        "source_document": graph_ids[ids["document"]],
        "derivation": "any_support",
        "provenance": [graph_ids[ids["chunk"]]],
        "subject_resource_id": ids["subject"],
        "object_resource_id": ids["target"],
        "source_document_resource_id": ids["document"],
        "source_version": SOURCE_VERSION,
        "provenance_resource_ids": [ids["chunk"]],
        "supports": [{
            "support_key": support_key,
            "provenance": [graph_ids[ids["chunk"]]],
            "provenance_resource_ids": [ids["chunk"]],
        }],
    }

    payloads = {
        "build_report.md": b"# Deterministic permissioned binary fixture\n",
        "claim_bindings.jsonl": jsonl_bytes([claim_binding]),
        "claims.jsonl": jsonl_bytes([{
            "claim_id": ids["claim"], "text": claim_text, "confidence": "high",
            "evidence_chunk_ids": [ids["chunk"]],
        }]),
        "chunks.jsonl": jsonl_bytes([{
            "chunk_id": ids["chunk"], "document_id": ids["document"],
            "span": [0, len(chunk_text)], "text": chunk_text,
            "hash": sha256_hex(chunk_text.encode("utf-8")),
        }]),
        "documents.jsonl": jsonl_bytes([{
            "document_id": ids["document"], "path": "sources/permissioned-binary.md",
            "content_hash": sha256_hex(document_text.encode("utf-8")),
            "title": "Permissioned binary fixture", "mtime": GENERATED_AT,
        }]),
        "entities.jsonl": jsonl_bytes(sorted([
            {
                "entity_id": ids["subject"], "name": subject_text, "type": "fixture_subject",
                "aliases": [], "evidence_chunk_ids": [ids["chunk"]],
            },
            {
                "entity_id": ids["target"], "name": target_text, "type": "fixture_target",
                "aliases": [], "evidence_chunk_ids": [ids["document"]],
            },
        ], key=lambda value: value["entity_id"])),
        "graph_bindings.jsonl": jsonl_bytes(graph_bindings),
        "projection.json": json_bytes(projection),
        "relations.jsonl": b"",
        "schema.yaml": b"version: 2\nfixture: permissioned-binary\n",
        "summaries.jsonl": b"",
    }
    counts = {
        "build_report.md": 1,
        "claim_bindings.jsonl": 1,
        "claims.jsonl": 1,
        "chunks.jsonl": 1,
        "documents.jsonl": 1,
        "entities.jsonl": 2,
        "graph_bindings.jsonl": len(graph_bindings),
        "projection.json": len(resources),
        "schema.yaml": 1,
    }
    descriptors = [
        {
            "path": path,
            "sha256": sha256_hex(data),
            "count": counts.get(path, 0),
            "size_bytes": len(data),
        }
        for path, data in sorted(payloads.items())
    ]
    manifest = {
        "version": 2,
        "projection_id": PROJECTION_ID,
        "projection_version": PROJECTION_ID,
        "namespace": "KnotePermissionedBinary",
        "authz_object": "knowledge-base:" + KNOWLEDGE_BASE_ID,
        "authz_version": ACL_VERSION,
        "graph_binding_contract_version": 2,
        "source_snapshot": {
            "version": SOURCE_VERSION,
            "digest": snapshot_digest,
            "document_count": 1,
        },
        "generated_at": GENERATED_AT,
        "files": descriptors,
        "v1_compatibility": {
            "version": 1,
            "workspace": KNOWLEDGE_BASE_ID,
            "generated_at": GENERATED_AT,
            "source_count": 1,
            "document_count": 1,
            "chunk_count": 1,
            "entity_count": 2,
            "relation_count": 0,
            "claim_count": 1,
            "summary_count": 0,
        },
    }

    bundle_dir = workspace / "artifacts" / "bundles" / PROJECTION_ID
    bundle_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    bundle_dir.chmod(0o700)
    for path, data in payloads.items():
        write_private(bundle_dir / path, data)
    manifest_data = json_bytes(manifest)
    write_private(bundle_dir / "manifest.json", manifest_data)
    manifest_digest = sha256_hex(manifest_data)
    write_private(
        workspace / "artifacts" / "current.json",
        json_bytes({
            "version": 2,
            "projection_id": PROJECTION_ID,
            "projection_version": PROJECTION_ID,
            "manifest_sha256": manifest_digest,
        }),
    )
    write_private(workspace / "sources" / "permissioned-binary.md", document_text.encode("utf-8"))

    return FixtureState(
        workspace=workspace,
        subject_graph_id=graph_ids[ids["subject"]],
        resource_ids=tuple(sorted((*ids.values(), *graph_ids.values()))),
        manifest_digest=manifest_digest,
    )


class _QuietThreadingHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, _request: Any, _client_address: Any) -> None:
        state = getattr(self, "state", None)
        if state is not None:
            state.record_server_error()


class LocalHTTPServer:
    def __init__(self, handler: type[http.server.BaseHTTPRequestHandler], state: Any) -> None:
        self.server = _QuietThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.server.state = state  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.server.serve_forever, name="knote-acceptance-http", daemon=True)

    @property
    def url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> "LocalHTTPServer":
        self.thread.start()
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _tb: Any) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class ModelState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.requests = 0
        self.authorized_tool_results = 0
        self.server_errors = 0
        self.tool_calls: dict[str, int] = {}
        self.bound_tool_results: dict[str, int] = {}

    def record(self, authorized_tool_result: bool, tool_name: str, tool_result: bool) -> int:
        with self.lock:
            self.requests += 1
            target = self.bound_tool_results if tool_result else self.tool_calls
            target[tool_name] = target.get(tool_name, 0) + 1
            if authorized_tool_result:
                self.authorized_tool_results += 1
            return self.requests

    def snapshot(self) -> tuple[int, int, int]:
        with self.lock:
            return self.requests, self.authorized_tool_results, self.server_errors

    def tool_snapshot(self) -> tuple[dict[str, int], dict[str, int]]:
        with self.lock:
            return dict(self.tool_calls), dict(self.bound_tool_results)

    def record_server_error(self) -> None:
        with self.lock:
            self.server_errors += 1


def model_handler() -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args: Any) -> None:
            return

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler contract
            state: ModelState = self.server.state  # type: ignore[attr-defined]
            if not self.path.endswith("/chat/completions"):
                self._json(404, {"error": {"message": "not found"}})
                return
            if self.headers.get("Authorization") != "Bearer " + OPENAI_API_KEY:
                self._json(401, {"error": {"message": "unauthorized"}})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                require(0 < length <= 2_000_000, "model", "invalid_request_size")
                body = json.loads(self.rfile.read(length))
                messages = body.get("messages")
                require(isinstance(messages, list) and messages, "model", "missing_messages")
                tool_result = messages[-1].get("role") == "tool"
                tool_name = _selected_model_tool(messages, tool_result)
                require(tool_name in {"knote_query", "knote_explain"}, "model", "tool_selection")
                content = messages[-1].get("content", "") if tool_result else ""
                authorized = tool_result and isinstance(content, str) and PROVIDER_ANSWER in content
                sequence = state.record(authorized, tool_name, tool_result)
                if tool_result:
                    if not authorized:
                        answer = UNBOUND_MODEL_CANARY
                    elif tool_name == "knote_explain":
                        answer = EXPLAIN_TUI_ANSWER
                    else:
                        answer = AUTHORIZED_TUI_ANSWER
                    self._json(200, _chat_response(sequence, answer=answer))
                    return
                tools = body.get("tools")
                names = {
                    item.get("function", {}).get("name")
                    for item in tools if isinstance(item, dict)
                } if isinstance(tools, list) else set()
                require(tool_name in names, "model", "permissioned_tool_missing")
                self._json(200, _chat_response(sequence, tool_call=True, tool_name=tool_name))
            except BaseException:
                state.record_server_error()
                self._json(500, {"error": {"message": "deterministic model failure"}})

        def _json(self, status: int, value: dict[str, Any]) -> None:
            data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(data)

    return Handler


def _selected_model_tool(messages: list[Any], tool_result: bool) -> str:
    if tool_result:
        for message in reversed(messages):
            if not isinstance(message, dict):
                continue
            calls = message.get("tool_calls")
            if not isinstance(calls, list):
                continue
            for call in calls:
                if isinstance(call, dict):
                    name = call.get("function", {}).get("name")
                    if isinstance(name, str):
                        return name
        return ""
    for message in reversed(messages):
        if not isinstance(message, dict) or message.get("role") != "user":
            continue
        return "knote_explain" if message.get("content") == EXPLAIN_PROMPT else "knote_query"
    return ""


def _chat_response(
    sequence: int,
    *,
    answer: str = "",
    tool_call: bool = False,
    tool_name: str = "knote_query",
) -> dict[str, Any]:
    message: dict[str, Any] = {"role": "assistant", "content": answer or None}
    finish_reason = "stop"
    if tool_call:
        finish_reason = "tool_calls"
        message["tool_calls"] = [{
            "id": f"call_permissioned_binary_{sequence}",
            "type": "function",
            "function": {
                "name": tool_name,
                "arguments": json.dumps({
                    "question": (
                        "Explain the permissioned binary answer."
                        if tool_name == "knote_explain"
                        else "What is the permissioned binary answer?"
                    )
                }),
            },
        }]
    return {
        "id": f"chatcmpl-permissioned-binary-{sequence}",
        "object": "chat.completion",
        "created": 0,
        "model": "knote-permissioned-binary",
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }


class OpenFGAState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.mode = "allow"
        self.requests = 0
        self.server_errors = 0
        self.tuples: set[tuple[str, str, str]] = set()

    def set_mode(self, mode: str) -> None:
        require(mode in {"allow", "deny", "backend_failure"}, "openfga", "invalid_mode")
        with self.lock:
            self.mode = mode

    def record_request(self) -> str:
        with self.lock:
            self.requests += 1
            return self.mode

    def snapshot(self) -> tuple[str, int, int]:
        with self.lock:
            return self.mode, self.requests, self.server_errors

    def record_server_error(self) -> None:
        with self.lock:
            self.server_errors += 1

    def read_tuples(self, key: dict[str, Any]) -> list[tuple[str, str, str]]:
        user = key.get("user", "")
        relation = key.get("relation", "")
        object_name = key.get("object", "")
        require(all(isinstance(value, str) for value in (user, relation, object_name)), "openfga", "read_filter_invalid")
        with self.lock:
            return sorted(
                item for item in self.tuples
                if (not user or item[0] == user)
                and (not relation or item[1] == relation)
                and (not object_name or item[2] == object_name)
            )

    def apply_tuples(
        self,
        writes: list[tuple[str, str, str]],
        deletes: list[tuple[str, str, str]],
        duplicate_policy: str,
        missing_policy: str,
    ) -> bool:
        with self.lock:
            if duplicate_policy == "error" and any(item in self.tuples for item in writes):
                return False
            if missing_policy == "error" and any(item not in self.tuples for item in deletes):
                return False
            for item in deletes:
                self.tuples.discard(item)
            self.tuples.update(writes)
            return True


def _openfga_tuple(value: Any) -> tuple[str, str, str]:
    require(isinstance(value, dict), "openfga", "tuple_invalid")
    require(set(value) == {"user", "relation", "object"}, "openfga", "tuple_fields_invalid")
    user = value.get("user")
    relation = value.get("relation")
    object_name = value.get("object")
    require(
        all(isinstance(item, str) and item for item in (user, relation, object_name)),
        "openfga",
        "tuple_value_invalid",
    )
    return user, relation, object_name


def _identity_publication_fence(value: tuple[str, str, str]) -> tuple[str, int]:
    user, relation, object_name = value
    prefix = "identity_control:publication_v1_"
    require(
        relation == "claimed" and object_name == "identity_control:membership" and user.startswith(prefix),
        "openfga",
        "identity_publication_fence_invalid",
    )
    parts = user.removeprefix(prefix).split("_")
    require(
        len(parts) == 5
        and parts[0] in {"a", "p"}
        and re.fullmatch(r"[0-9]{20}", parts[1]) is not None
        and re.fullmatch(r"[0-9]{20}", parts[2]) is not None
        and re.fullmatch(r"[0-9a-f]{32}", parts[3]) is not None
        and re.fullmatch(r"[0-9a-f]{64}", parts[4]) is not None,
        "openfga",
        "identity_publication_fence_invalid",
    )
    attempt = int(parts[1])
    revision = int(parts[2])
    require(
        revision > 0 and attempt > 0,
        "openfga",
        "identity_publication_fence_invalid",
    )
    return parts[0], attempt


def openfga_handler() -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args: Any) -> None:
            return

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler contract
            state: OpenFGAState = self.server.state  # type: ignore[attr-defined]
            mode = state.record_request()
            if self.headers.get("Authorization") != "Bearer " + OPENFGA_API_TOKEN:
                self._json(401, {"code": "unauthorized", "message": "unauthorized"})
                return
            if mode == "backend_failure":
                self._json(503, {"code": "unavailable", "message": BACKEND_FAILURE_SECRET})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                require(0 < length <= 2_000_000, "openfga", "invalid_request_size")
                body = json.loads(self.rfile.read(length))
                allowed = mode == "allow"
                if self.path == f"/stores/{STORE_ID}/read":
                    require(body.get("page_size") == 100, "openfga", "read_page_size_invalid")
                    require(
                        body.get("consistency") == "HIGHER_CONSISTENCY",
                        "openfga",
                        "read_consistency_invalid",
                    )
                    require(not body.get("continuation_token"), "openfga", "unexpected_continuation")
                    key = body.get("tuple_key")
                    require(isinstance(key, dict), "openfga", "read_filter_invalid")
                    tuples = [
                        {
                            "key": {"user": user, "relation": relation, "object": object_name},
                            "timestamp": "2026-07-17T00:00:00Z",
                        }
                        for user, relation, object_name in state.read_tuples(key)
                    ]
                    self._json(200, {"tuples": tuples, "continuation_token": ""})
                    return
                if self.path == f"/stores/{STORE_ID}/write":
                    require(
                        body.get("authorization_model_id") == MODEL_ID,
                        "openfga",
                        "write_model_mismatch",
                    )
                    writes = body.get("writes")
                    deletes = body.get("deletes")
                    write_tuples: list[Any] = []
                    delete_tuples: list[Any] = []
                    if writes is not None:
                        require(isinstance(writes, dict), "openfga", "writes_invalid")
                        write_tuples = writes.get("tuple_keys", [])
                        require(isinstance(write_tuples, list), "openfga", "write_tuples_invalid")
                    if deletes is not None:
                        require(isinstance(deletes, dict), "openfga", "deletes_invalid")
                        delete_tuples = deletes.get("tuple_keys", [])
                        require(isinstance(delete_tuples, list), "openfga", "delete_tuples_invalid")
                    require(write_tuples or delete_tuples, "openfga", "empty_tuple_write")
                    canonical_writes = [_openfga_tuple(item) for item in write_tuples]
                    canonical_deletes = [_openfga_tuple(item) for item in delete_tuples]
                    fixed_claim = ("identity_control:claim", "claimed", "identity_control:membership")
                    tenant_binding = (f"identity_tenant:{TENANT_ID}", "tenant", "identity_control:membership")
                    control_writes = [item for item in canonical_writes if item[2] == "identity_control:membership"]
                    control_deletes = [item for item in canonical_deletes if item[2] == "identity_control:membership"]
                    if fixed_claim in canonical_writes:
                        require(not canonical_deletes, "openfga", "control_delete_invalid")
                        require(
                            writes.get("on_duplicate") == "error",
                            "openfga",
                            "control_duplicate_policy_invalid",
                        )
                        require(
                            len(canonical_writes) == 3
                            and canonical_writes[:2] == [fixed_claim, tenant_binding],
                            "openfga",
                            "control_claim_invalid",
                        )
                        state_name, attempt = _identity_publication_fence(canonical_writes[2])
                        require(state_name == "a" and attempt == 1, "openfga", "control_claim_fence_invalid")
                    elif control_writes or control_deletes:
                        require(
                            len(control_writes) == 1 and len(control_deletes) == 1,
                            "openfga",
                            "identity_publication_fence_count_invalid",
                        )
                        require(
                            writes is not None
                            and writes.get("on_duplicate") == "error"
                            and deletes is not None
                            and deletes.get("on_missing") == "error",
                            "openfga",
                            "identity_publication_conflict_policy_invalid",
                        )
                        _, previous_attempt = _identity_publication_fence(control_deletes[0])
                        _, next_attempt = _identity_publication_fence(control_writes[0])
                        require(
                            next_attempt == previous_attempt + 1,
                            "openfga",
                            "identity_publication_fence_not_monotonic",
                        )
                        require(
                            len(canonical_writes) + len(canonical_deletes) <= 100,
                            "openfga",
                            "identity_publication_batch_too_large",
                        )
                        for user, relation, object_name in canonical_writes + canonical_deletes:
                            if object_name == "identity_control:membership":
                                continue
                            require(
                                user.startswith("user:")
                                and relation == "member"
                                and object_name.startswith("group:"),
                                "openfga",
                                "identity_membership_tuple_invalid",
                            )
                    else:
                        require(
                            writes is None or writes.get("on_duplicate") == "ignore",
                            "openfga",
                            "duplicate_policy_invalid",
                        )
                        require(
                            deletes is None or deletes.get("on_missing") == "ignore",
                            "openfga",
                            "missing_delete_policy_invalid",
                        )
                        for user, relation, object_name in canonical_writes + canonical_deletes:
                            require(
                                user.startswith("user:")
                                and relation == "member"
                                and object_name.startswith("group:"),
                                "openfga",
                                "identity_membership_tuple_invalid",
                            )
                    duplicate_policy = writes.get("on_duplicate", "error") if writes is not None else "error"
                    missing_policy = deletes.get("on_missing", "error") if deletes is not None else "error"
                    if not state.apply_tuples(
                        canonical_writes,
                        canonical_deletes,
                        duplicate_policy,
                        missing_policy,
                    ):
                        self._json(409, {"code": "write_failed_due_to_invalid_input", "message": "tuple conflict"})
                        return
                    self._json(200, {})
                    return
                if self.path == f"/stores/{STORE_ID}/batch-check":
                    checks = body.get("checks")
                    require(isinstance(checks, list) and checks, "openfga", "missing_checks")
                    result: dict[str, dict[str, bool]] = {}
                    for check in checks:
                        correlation = check.get("correlation_id") if isinstance(check, dict) else None
                        require(isinstance(correlation, str) and correlation, "openfga", "missing_correlation")
                        require(correlation not in result, "openfga", "duplicate_correlation")
                        result[correlation] = {"allowed": allowed}
                    self._json(200, {"result": result})
                    return
                if self.path == f"/stores/{STORE_ID}/check":
                    self._json(200, {"allowed": allowed})
                    return
                self._json(404, {"code": "not_found", "message": "not found"})
            except BaseException:
                state.record_server_error()
                self._json(500, {"code": "internal", "message": "deterministic OpenFGA failure"})

        def _json(self, status: int, value: dict[str, Any]) -> None:
            data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(data)

    return Handler


def write_control(path: Path, mode: str) -> None:
    temporary = path.with_suffix(".tmp")
    write_private(temporary, json_bytes({"mode": mode}))
    os.replace(temporary, path)
    path.chmod(0o600)


def provider_counts(path: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    if not path.exists():
        return counts
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AcceptanceError("provider", "invalid_stats") from exc
        operation = value.get("operation") if isinstance(value, dict) else None
        require(operation in {"retrieve", "generate"}, "provider", "invalid_stats_operation")
        counts[operation] = counts.get(operation, 0) + 1
    return counts


def provider_delta(before: dict[str, int], after: dict[str, int], operation: str) -> int:
    return after.get(operation, 0) - before.get(operation, 0)


def build_environment(
    root: Path,
    fixture_dir: Path,
    fixture: FixtureState,
    identity_fixture: IdentityFixture,
    control: Path,
    stats: Path,
    model_url: str,
    openfga_url: str,
    telemetry_path: Path | None = None,
) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("KNOTE_KAG_FAKE", None)
    env.pop(TELEMETRY_ENV, None)
    env.pop("KNOTE_PERMISSIONED_PRINCIPAL", None)
    env.pop("KNOTE_PERMISSIONED_IDENTITY_WATERMARK", None)
    env.pop("KNOTE_IDENTITY_ASSERTION_FD", None)
    env.update({
        "TERM": "xterm-256color",
        "COLUMNS": "120",
        "LINES": "40",
        "KNOTE_RUNTIME_MODE": "eino",
        "KNOTE_PERMISSIONED": "1",
        "KNOTE_IDENTITY_STORE_PATH": str(identity_fixture.store_path),
        "KNOTE_IDENTITY_ED25519_PUBLIC_KEY": identity_fixture.public_key,
        "KNOTE_KAG_PERMISSIONED_PROVIDER": "permissioned_binary_provider:create",
        "KNOTE_PERMISSIONED_BINARY_CONTROL": str(control),
        "KNOTE_PERMISSIONED_BINARY_STATS": str(stats),
        "KNOTE_PERMISSIONED_BINARY_SUBJECT_GRAPH_ID": fixture.subject_graph_id,
        "KNOTE_PERMISSIONED_BINARY_PROVIDER_ANSWER": PROVIDER_ANSWER,
        "KNOTE_PERMISSIONED_BINARY_EXPECTED_CONTENT": PROTECTED_CONTENT,
        "KNOTE_PERMISSIONED_BINARY_PROVIDER_SECRET": PROVIDER_FAILURE_SECRET,
        "KNOTE_OPENFGA_ENDPOINT": openfga_url,
        "KNOTE_OPENFGA_STORE_ID": STORE_ID,
        "KNOTE_OPENFGA_MODEL_ID": MODEL_ID,
        "KNOTE_OPENFGA_TIMEOUT": "1s",
        "KNOTE_OPENFGA_CONSISTENCY": "higher_consistency",
        "KNOTE_OPENFGA_API_TOKEN": OPENFGA_API_TOKEN,
        "KNOTE_EINO_PROVIDER": "openai-compatible",
        "KNOTE_EINO_MODEL": "knote-permissioned-binary",
        "KNOTE_EINO_BASE_URL": model_url + "/v1",
        "KNOTE_EINO_API_KEY": OPENAI_API_KEY,
        "KNOTE_PYTHON": sys.executable,
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    existing_python_path = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(fixture_dir) + (os.pathsep + existing_python_path if existing_python_path else "")
    if telemetry_path is not None:
        require(telemetry_path.is_absolute(), "preflight", "telemetry_path_not_absolute")
        env[TELEMETRY_ENV] = str(telemetry_path)
    require("KNOTE_KAG_FAKE" not in env, "preflight", "fake_mode_present")
    require((root / "adapters" / "kag" / "knote_kag_adapter.py").is_file(), "preflight", "adapter_missing")
    return env


def set_pty_size(driver: PTYDriver) -> None:
    fcntl.ioctl(driver.master, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
    with contextlib.suppress(ProcessLookupError):
        os.kill(driver.pid, signal.SIGWINCH)


@contextlib.contextmanager
def running_driver(
    binary: Path,
    root: Path,
    workspace: Path,
    env: dict[str, str],
    identity_fixture: IdentityFixture,
    resume: str = "",
) -> Iterator[PTYDriver]:
    command = [str(binary), "--workspace", str(workspace)]
    if resume:
        command.extend(["--resume", resume])
    assertion = identity_fixture.take_assertion().open("rb")
    descriptor = assertion.fileno()
    child_env = env.copy()
    child_env["KNOTE_IDENTITY_ASSERTION_FD"] = str(descriptor)
    try:
        os.set_inheritable(descriptor, True)
        driver = PTYDriver(command, env=child_env, cwd=root)
    finally:
        os.set_inheritable(descriptor, False)
        assertion.close()
    set_pty_size(driver)
    try:
        yield driver
    finally:
        driver.close()


def expect_startup(driver: PTYDriver, timeout: float = 20) -> None:
    driver.read_once(0.5)
    if not driver.clean():
        driver.poke("\r")
    driver.expect("session ready", timeout=timeout)


def expect_startup_failure(driver: PTYDriver, timeout: float = 20) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        driver.read_once(0.1)
        code = driver.poll()
        if code is None:
            continue
        output = driver.clean()
        require(code != 0, "startup", "failure_returned_success")
        require(FAILURE_MESSAGE in output, "startup", "generic_failure_missing")
        require("session ready" not in output, "startup", "tui_started_after_failure")
        return output
    raise AcceptanceError("startup", "failure_timeout")


def run_query(
    driver: PTYDriver,
    expected: str,
    timeout: float = 35,
    alternate: str = "",
    prompt: str = QUERY_PROMPT,
) -> tuple[str, str]:
    driver.send(prompt + "\r")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        driver.read_once(0.1)
        output = driver.clean()
        window = output[driver.offset :]
        if expected in window:
            driver.read_once(0.2)
            return driver.clean(), expected
        if alternate and alternate in window:
            driver.read_once(0.2)
            return driver.clean(), alternate
        code = driver.poll()
        if code is not None:
            raise AcceptanceError("pty", "early_exit", f"exit={code}")
    raise AcceptanceError("pty", "query_timeout")


def stage_evidence(
    provider_before: dict[str, int],
    provider_after: dict[str, int],
    model_before: tuple[int, int, int],
    model_after: tuple[int, int, int],
    fga_before: int,
    fga_after: int,
) -> str:
    values = {
        "fga": fga_after - fga_before,
        "provider_retrieve": provider_delta(provider_before, provider_after, "retrieve"),
        "provider_generate": provider_delta(provider_before, provider_after, "generate"),
        "model": model_after[0] - model_before[0],
        "model_bound_result": model_after[1] - model_before[1],
    }
    return ",".join(f"{name}={values[name]}" for name in sorted(values))


def session_text(workspace: Path) -> str:
    session_dir = workspace / ".knote" / "sessions"
    return "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in sorted(session_dir.glob("*.jsonl"))
    )


def leak_markers(fixture: FixtureState) -> tuple[str, ...]:
    return fixture.protected_markers + (
        fixture.subject_graph_id,
        PRINCIPAL_ID,
        OPENAI_API_KEY,
        OPENFGA_API_TOKEN,
        PROVIDER_FAILURE_SECRET,
        BACKEND_FAILURE_SECRET,
        STORE_ID,
        MODEL_ID,
    )


def assert_no_leaks(text: str, fixture: FixtureState, stage: str) -> None:
    for marker in leak_markers(fixture):
        if marker and marker in text:
            raise AcceptanceError(stage, "protected_marker_leak")


def telemetry_forbidden_markers(fixture: FixtureState) -> tuple[str, ...]:
    return leak_markers(fixture) + (
        TENANT_ID,
        KNOWLEDGE_BASE_ID,
        PROJECTION_ID,
        SOURCE_VERSION,
        ACL_VERSION,
        IDENTITY_WATERMARK,
        SECURITY_DOMAIN,
        SUPPORT_ID,
        QUERY_PROMPT,
        AUTHORIZED_TUI_ANSWER,
        FAILURE_MESSAGE,
    )


def read_telemetry_records(path: Path, fixture: FixtureState) -> list[dict[str, Any]]:
    require(path.is_absolute(), "telemetry", "path_not_absolute")
    require(path.is_file(), "telemetry", "sink_missing")
    try:
        payload = path.read_bytes()
        text = payload.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise AcceptanceError("telemetry", "sink_unreadable") from exc
    require(payload.endswith(b"\n"), "telemetry", "jsonl_missing_newline")
    for marker in telemetry_forbidden_markers(fixture):
        if marker and marker in text:
            raise AcceptanceError("telemetry", "protected_marker_leak")

    lines = text.splitlines()
    require(bool(lines) and all(line.strip() for line in lines), "telemetry", "jsonl_blank_record")
    records: list[dict[str, Any]] = []
    for line in lines:
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AcceptanceError("telemetry", "invalid_jsonl") from exc
        require(type(record) is dict, "telemetry", "record_not_object")
        require(set(record) == TELEMETRY_ALLOWED_FIELDS, "telemetry", "field_set_mismatch")
        for field in TELEMETRY_INTEGER_FIELDS:
            value = record[field]
            require(type(value) is int and value >= 0, "telemetry", "invalid_integer")
        require(record["contract_version"] == 1, "telemetry", "contract_version")
        for field in TELEMETRY_NUMBER_FIELDS:
            value = record[field]
            require(
                type(value) in {int, float} and math.isfinite(value) and 0 <= value <= 1,
                "telemetry",
                "invalid_rate",
            )
        for field, allowed in TELEMETRY_ENUM_FIELDS.items():
            require(type(record[field]) is str and record[field] in allowed, "telemetry", "invalid_enum")
        require(
            record["candidate_count"] == record["allowed_count"] + record["dropped_count"],
            "telemetry",
            "candidate_count_balance",
        )
        require(
            record["final_filter_candidate_count"]
            == record["final_filter_allowed_count"] + record["final_filter_dropped_count"],
            "telemetry",
            "final_filter_count_balance",
        )
        require(
            record["complete_path_count"] <= record["selected_path_count"],
            "telemetry",
            "complete_path_count",
        )
        records.append(record)
    return records


def assert_query_telemetry(
    path: Path,
    fixture: FixtureState,
    expected_outcome: str,
) -> int:
    records = read_telemetry_records(path, fixture)
    require(len(records) == 1, "telemetry", "record_count")
    record = records[0]
    require(record["event"] == "permissioned_query", "telemetry", "event")
    require(record["metric_scope"] == "operational", "telemetry", "metric_scope")
    require(record["stage"] == "traversal", "telemetry", "stage")
    require(record["outcome"] == expected_outcome, "telemetry", "outcome")
    require(record["sample_count"] == 1, "telemetry", "sample_count")
    for field in (
        "unauthorized_path_count",
        "unauthorized_generator_count",
        "recall_at_4",
        "precision_at_4",
        "positive_empty_rate",
        "negative_empty_rate",
        "p95_ms",
        "p99_ms",
        "revocation_p95_ms",
        "revocation_p99_ms",
    ):
        require(record[field] == 0, "telemetry", "cohort_metric_in_operational_record")
    if expected_outcome == "allowed":
        require(record["evidence_item_count"] >= 1, "telemetry", "allowed_evidence_count")
        require(record["complete_path_count"] >= 1, "telemetry", "allowed_path_count")
    elif expected_outcome == "denied":
        require(record["evidence_item_count"] == 0, "telemetry", "denied_evidence_count")
    return len(records)


def assert_server_health(model: ModelState, openfga: OpenFGAState) -> None:
    require(model.snapshot()[2] == 0, "model", "server_error")
    require(openfga.snapshot()[2] == 0, "openfga", "server_error")


def build_binary(root: Path, destination: Path, timeout: float) -> None:
    env = os.environ.copy()
    env.pop("KNOTE_KAG_FAKE", None)
    env["CGO_ENABLED"] = "0"
    try:
        completed = subprocess.run(
            ["go", "build", "-trimpath", "-o", str(destination), "./cmd/knote"],
            cwd=root,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AcceptanceError("build", "go_build_failed") from exc
    require(completed.returncode == 0, "build", "go_build_failed", completed.stderr[-2000:])
    require(destination.is_file() and os.access(destination, os.X_OK), "build", "binary_missing")


def verify_binary(binary: Path, root: Path) -> None:
    env = os.environ.copy()
    env.pop("KNOTE_KAG_FAKE", None)
    try:
        completed = subprocess.run(
            [str(binary), "--version"], cwd=root, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AcceptanceError("preflight", "binary_unusable") from exc
    require(completed.returncode == 0 and "version=" in completed.stdout, "preflight", "binary_unusable")


def run_self_test(root: Path) -> dict[str, Any]:
    provider = root / "tests" / "fixtures" / "permissioned-binary" / "permissioned_binary_provider.py"
    require(provider.is_file(), "self_test", "provider_missing")
    try:
        compile(provider.read_text(encoding="utf-8"), str(provider), "exec")
    except (OSError, SyntaxError) as exc:
        raise AcceptanceError("self_test", "provider_invalid") from exc
    with tempfile.TemporaryDirectory(prefix="knote-permissioned-binary-selftest-") as first, tempfile.TemporaryDirectory(
        prefix="knote-permissioned-binary-selftest-repeat-"
    ) as second:
        left = materialize_workspace(Path(first))
        right = materialize_workspace(Path(second))
        require(left.manifest_digest == right.manifest_digest, "self_test", "manifest_nondeterministic")
        left_files = {
            path.relative_to(left.workspace).as_posix(): path.read_bytes()
            for path in sorted((left.workspace / "artifacts").rglob("*")) if path.is_file()
        }
        right_files = {
            path.relative_to(right.workspace).as_posix(): path.read_bytes()
            for path in sorted((right.workspace / "artifacts").rglob("*")) if path.is_file()
        }
        require(left_files == right_files, "self_test", "fixture_nondeterministic")
    return {"mode": "self-test", "status": "pass", "fixture": "permissioned-binary-v1"}


def run_acceptance(root: Path, binary: Path, run_root: Path) -> dict[str, Any]:
    fixture_dir = root / "tests" / "fixtures" / "permissioned-binary"
    control = run_root / "provider-control.json"
    stats = run_root / "provider-stats.jsonl"
    write_control(control, "success")
    write_private(stats, b"")
    identity_fixture = initialize_identity_fixture(root, run_root)

    allowed = materialize_workspace(run_root / "workspace-allowed")
    denied = materialize_workspace(run_root / "workspace-denied")
    empty_result = materialize_workspace(run_root / "workspace-empty-result")
    telemetry_failure = materialize_workspace(run_root / "workspace-telemetry-failure")
    provider_failure = materialize_workspace(run_root / "workspace-provider-failure")
    backend_failure = materialize_workspace(run_root / "workspace-backend-failure")

    model_state = ModelState()
    openfga_state = OpenFGAState()
    cases: list[str] = []
    with LocalHTTPServer(model_handler(), model_state) as model_server, LocalHTTPServer(
        openfga_handler(), openfga_state
    ) as openfga_server:
        def environment(
            fixture: FixtureState,
            telemetry_path: Path | None = None,
        ) -> dict[str, str]:
            return build_environment(
                root,
                fixture_dir,
                fixture,
                identity_fixture,
                control,
                stats,
                model_server.url,
                openfga_server.url,
                telemetry_path,
            )

        openfga_state.set_mode("allow")
        write_control(control, "success")
        allowed_telemetry = run_root / "telemetry-allowed.jsonl"
        provider_before = provider_counts(stats)
        model_before = model_state.snapshot()
        fga_before = openfga_state.snapshot()[1]
        with running_driver(
            binary,
            root,
            allowed.workspace,
            environment(allowed, allowed_telemetry),
            identity_fixture,
        ) as driver:
            expect_startup(driver)
            output, observed = run_query(
                driver, AUTHORIZED_TUI_ANSWER, alternate=FAILURE_MESSAGE
            )
            session_id = latest_session_id(allowed.workspace)
        provider_after = provider_counts(stats)
        model_after = model_state.snapshot()
        fga_after = openfga_state.snapshot()[1]
        require(
            observed == AUTHORIZED_TUI_ANSWER,
            "authorized_query",
            "fail_closed",
            stage_evidence(
                provider_before,
                provider_after,
                model_before,
                model_after,
                fga_before,
                fga_after,
            ),
        )
        assert_no_leaks(output.replace(AUTHORIZED_TUI_ANSWER, ""), allowed, "authorized_query")
        require(provider_delta(provider_before, provider_after, "retrieve") == 1, "authorized_query", "retrieve_count")
        require(provider_delta(provider_before, provider_after, "generate") == 1, "authorized_query", "generate_count")
        require(model_after[1] == model_before[1] + 1, "authorized_query", "model_tool_result_missing")
        require(fga_after > fga_before, "authorized_query", "authorization_not_called")
        assert_query_telemetry(allowed_telemetry, allowed, "allowed")
        cases.append("authorized_query")

        provider_before = provider_counts(stats)
        model_before = model_state.snapshot()
        fga_before = openfga_state.snapshot()[1]
        with running_driver(binary, root, allowed.workspace, environment(allowed), identity_fixture) as driver:
            expect_startup(driver)
            output, observed = run_query(
                driver,
                EXPLAIN_TUI_ANSWER,
                alternate=FAILURE_MESSAGE,
                prompt=EXPLAIN_PROMPT,
            )
        provider_after = provider_counts(stats)
        model_after = model_state.snapshot()
        fga_after = openfga_state.snapshot()[1]
        require(observed == EXPLAIN_TUI_ANSWER, "authorized_explain", "fail_closed")
        assert_no_leaks(output.replace(EXPLAIN_TUI_ANSWER, ""), allowed, "authorized_explain")
        require(provider_delta(provider_before, provider_after, "retrieve") == 1, "authorized_explain", "retrieve_count")
        require(provider_delta(provider_before, provider_after, "generate") == 1, "authorized_explain", "generate_count")
        require(model_after[1] == model_before[1] + 1, "authorized_explain", "model_tool_result_missing")
        require(fga_after > fga_before, "authorized_explain", "authorization_not_called")
        cases.append("authorized_explain")

        fga_before = openfga_state.snapshot()[1]
        with running_driver(
            binary, root, allowed.workspace, environment(allowed), identity_fixture, session_id
        ) as driver:
            expect_startup(driver)
            driver.expect(AUTHORIZED_TUI_ANSWER, timeout=10)
            output = driver.clean()
        assert_no_leaks(output.replace(AUTHORIZED_TUI_ANSWER, ""), allowed, "authorized_resume")
        require(openfga_state.snapshot()[1] > fga_before, "authorized_resume", "replay_not_reauthorized")
        cases.append("authorized_resume")

        openfga_state.set_mode("deny")
        write_control(control, "success")
        denied_telemetry = run_root / "telemetry-denied.jsonl"
        provider_before = provider_counts(stats)
        with running_driver(
            binary,
            root,
            denied.workspace,
            environment(denied, denied_telemetry),
            identity_fixture,
        ) as driver:
            expect_startup(driver)
            output, _observed = run_query(driver, FAILURE_MESSAGE)
        require(provider_counts(stats) == provider_before, "denied_query", "provider_called_after_deny")
        assert_no_leaks(output, denied, "denied_query")
        assert_no_leaks(session_text(denied.workspace), denied, "denied_session")
        assert_query_telemetry(denied_telemetry, denied, "denied")
        cases.append("denied_query")

        fga_before = openfga_state.snapshot()[1]
        with running_driver(
            binary, root, allowed.workspace, environment(allowed), identity_fixture, session_id
        ) as driver:
            expect_startup(driver)
            driver.read_once(0.5)
            output = driver.clean()
        require(openfga_state.snapshot()[1] > fga_before, "revoked_resume", "replay_not_reauthorized")
        require(AUTHORIZED_TUI_ANSWER not in output, "revoked_resume", "revoked_answer_replayed")
        assert_no_leaks(output, allowed, "revoked_resume")
        cases.append("revoked_resume")

        previous_identity_watermark = identity_fixture.identity_watermark
        current_identity_watermark = bump_identity_fixture(root, identity_fixture)
        require(
            current_identity_watermark != previous_identity_watermark,
            "permission_bound_resume",
            "identity_watermark_static",
        )
        with running_driver(
            binary,
            root,
            allowed.workspace,
            environment(allowed),
            identity_fixture,
            session_id,
        ) as mismatch_driver:
            mismatch_driver.expect("resume authorization failed", timeout=15)
            code = mismatch_driver.wait(timeout=5)
            output = mismatch_driver.clean()
        require(code != 0, "permission_bound_resume", "mismatch_was_accepted")
        assert_no_leaks(output, allowed, "permission_bound_resume")
        cases.append("permission_bound_resume")

        openfga_state.set_mode("allow")
        write_control(control, "empty")
        empty_telemetry = run_root / "telemetry-empty.jsonl"
        provider_before = provider_counts(stats)
        with running_driver(
            binary,
            root,
            empty_result.workspace,
            environment(empty_result, empty_telemetry),
            identity_fixture,
        ) as driver:
            expect_startup(driver)
            output, _observed = run_query(driver, FAILURE_MESSAGE)
        provider_after = provider_counts(stats)
        require(provider_delta(provider_before, provider_after, "retrieve") == 1, "empty_result", "retrieve_count")
        require(provider_delta(provider_before, provider_after, "generate") == 0, "empty_result", "generate_after_empty")
        assert_no_leaks(output, empty_result, "empty_result")
        assert_no_leaks(session_text(empty_result.workspace), empty_result, "empty_result_session")
        assert_query_telemetry(empty_telemetry, empty_result, "not_found")
        cases.append("empty_result")

        write_control(control, "success")
        unwritable_telemetry = run_root / "missing-telemetry-directory" / "telemetry.jsonl"
        provider_before = provider_counts(stats)
        with running_driver(
            binary,
            root,
            telemetry_failure.workspace,
            environment(telemetry_failure, unwritable_telemetry),
            identity_fixture,
        ) as driver:
            expect_startup(driver)
            output, observed = run_query(
                driver, AUTHORIZED_TUI_ANSWER, alternate=FAILURE_MESSAGE
            )
        provider_after = provider_counts(stats)
        require(observed == AUTHORIZED_TUI_ANSWER, "telemetry_sink_failure", "query_changed")
        require(not unwritable_telemetry.exists(), "telemetry_sink_failure", "sink_unexpectedly_created")
        require(provider_delta(provider_before, provider_after, "retrieve") == 1, "telemetry_sink_failure", "retrieve_count")
        require(provider_delta(provider_before, provider_after, "generate") == 1, "telemetry_sink_failure", "generate_count")
        assert_no_leaks(
            output.replace(AUTHORIZED_TUI_ANSWER, ""),
            telemetry_failure,
            "telemetry_sink_failure",
        )
        cases.append("telemetry_sink_failure")

        write_control(control, "provider_failure")
        provider_before = provider_counts(stats)
        with running_driver(
            binary, root, provider_failure.workspace, environment(provider_failure), identity_fixture
        ) as driver:
            expect_startup(driver)
            output, _observed = run_query(driver, FAILURE_MESSAGE)
        provider_after = provider_counts(stats)
        require(
            provider_delta(provider_before, provider_after, "retrieve") == 1
            and provider_delta(provider_before, provider_after, "generate") == 0,
            "provider_failure", "provider_failure_boundary",
        )
        assert_no_leaks(output, provider_failure, "provider_failure")
        assert_no_leaks(session_text(provider_failure.workspace), provider_failure, "provider_failure_session")
        cases.append("provider_failure")

        openfga_state.set_mode("backend_failure")
        write_control(control, "success")
        provider_before = provider_counts(stats)
        with running_driver(
            binary, root, backend_failure.workspace, environment(backend_failure), identity_fixture
        ) as driver:
            output = expect_startup_failure(driver)
        require(provider_counts(stats) == provider_before, "backend_failure", "provider_called_after_backend_failure")
        assert_no_leaks(output, backend_failure, "backend_failure")
        assert_no_leaks(session_text(backend_failure.workspace), backend_failure, "backend_failure_session")
        cases.append("backend_failure")

        assert_server_health(model_state, openfga_state)

    return {
        "status": "pass",
        "mode": "built-binary",
        "fake_mode": False,
        "cases": cases,
        "case_count": len(cases),
    }


def sanitized_detail(exc: BaseException) -> str:
    text = " ".join(str(exc).split())
    for marker in (
        PROTECTED_CONTENT,
        PROTECTED_CLAIM,
        PROVIDER_ANSWER,
        UNBOUND_MODEL_CANARY,
        OPENAI_API_KEY,
        OPENFGA_API_TOKEN,
        PROVIDER_FAILURE_SECRET,
        BACKEND_FAILURE_SECRET,
        STORE_ID,
        MODEL_ID,
    ):
        text = text.replace(marker, "[redacted]")
    return text[-1000:]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    if "KNOTE_KAG_FAKE" in os.environ:
        raise AcceptanceError("preflight", "fake_mode_environment_present")
    require(args.timeout >= 30, "preflight", "timeout_too_small")

    root = Path(__file__).resolve().parents[2]
    if args.self_test:
        print(json.dumps(run_self_test(root), sort_keys=True, separators=(",", ":")), flush=True)
        return 0

    with tempfile.TemporaryDirectory(prefix="knote-permissioned-binary-") as temporary:
        run_root = Path(temporary)
        binary = args.bin.resolve() if args.bin else run_root / "knote"
        if args.bin is None:
            build_binary(root, binary, min(90, args.timeout / 2))
        verify_binary(binary, root)
        result = run_acceptance(root, binary, run_root)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)
    return 0


def _timeout(_signum: int, _frame: Any) -> None:
    raise AcceptanceError("timeout", "overall_timeout")


if __name__ == "__main__":
    try:
        parsed_timeout = 180
        for index, argument in enumerate(sys.argv[1:]):
            if argument == "--timeout" and index + 2 <= len(sys.argv[1:]):
                with contextlib.suppress(ValueError):
                    parsed_timeout = int(sys.argv[1:][index + 1])
        signal.signal(signal.SIGALRM, _timeout)
        signal.alarm(max(30, parsed_timeout))
        raise SystemExit(main())
    except AcceptanceError as exc:
        print(
            json.dumps(
                {"status": "fail", "stage": exc.stage, "code": exc.code, "detail": sanitized_detail(exc)},
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
            flush=True,
        )
        raise SystemExit(1)
    except Exception as exc:
        print(
            json.dumps(
                {"status": "fail", "stage": "unexpected", "code": type(exc).__name__, "detail": sanitized_detail(exc)},
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
            flush=True,
        )
        raise SystemExit(1)
