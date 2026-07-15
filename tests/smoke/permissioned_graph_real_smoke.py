#!/usr/bin/env python3
"""Opt-in real permissioned graph smoke with a deterministic offline self-test."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


GRAPH_BINDING_VERSION = 2
MAX_ITEMS = 100
FGA_MODULE = "github.com/openfga/cli"
NAMESPACE_PREFIX_RE = re.compile(r"[A-Za-z][A-Za-z0-9]{2,31}\Z")
PROJECTION_RE = re.compile(r"prj_[0-9a-f]{32}\Z")
RESOURCE_RE = re.compile(r"res_[0-9a-f]{32}\Z")
PREDICATE_RE = re.compile(r"pred_[0-9a-f]{32}\Z")
SUPPORT_RE = re.compile(r"sup_[0-9a-f]{32}\Z")
FIXTURE_FIELDS = {
    "acl_version",
    "classification",
    "content_version",
    "derivation",
    "knowledge_base_id",
    "organization_id",
    "predicate_key",
    "principal_id",
    "projection_id",
    "query",
    "question",
    "resources",
    "source_version",
    "support_key",
    "tenant_id",
    "version",
}
RESOURCE_FIXTURE_FIELDS = {"content", "name", "resource_id", "type"}
RESOURCE_FIELDS = {
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
RESOURCE_VERSION_FIELDS = {"source", "content", "acl", "index", "graph", "projection"}
EXPECTED_ROLES = {
    "source": "document",
    "subject": "entity",
    "target": "entity",
    "claim": "claim",
}


class SmokeError(Exception):
    def __init__(self, stage: str, code: str, *, exit_code: int = 1) -> None:
        super().__init__(code)
        self.stage = stage
        self.code = code
        self.exit_code = exit_code


@dataclass
class MaterializedFixture:
    workspace: Path
    fixture: dict[str, Any]
    resources: dict[str, dict[str, Any]]
    graph_ids: dict[str, str]
    evidence_paths: dict[str, Path]
    namespace: str
    manifest_digest: str


@dataclass
class ReplayCapsule:
    resources: tuple[dict[str, Any], ...]
    target: dict[str, Any]


def emit_safe(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")), flush=True)


def require(condition: bool, stage: str, code: str, *, preflight: bool = False) -> None:
    if not condition:
        raise SmokeError(stage, code, exit_code=2 if preflight else 1)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON field")
        value[key] = item
    return value


def load_json_object(path: Path, stage: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise SmokeError(stage, "invalid_json") from exc
    require(type(value) is dict, stage, "json_not_object")
    return value


def validate_fixture(fixture: dict[str, Any]) -> None:
    stage = "fixture"
    require(set(fixture) == FIXTURE_FIELDS, stage, "unexpected_fields")
    require(fixture["version"] == 1, stage, "unsupported_version")
    require(fixture["classification"] == "public-synthetic", stage, "not_sanitized")
    require(PROJECTION_RE.fullmatch(str(fixture["projection_id"])) is not None, stage, "invalid_projection")
    require(PREDICATE_RE.fullmatch(str(fixture["predicate_key"])) is not None, stage, "invalid_predicate")
    require(SUPPORT_RE.fullmatch(str(fixture["support_key"])) is not None, stage, "invalid_support")
    require(fixture["derivation"] in {"any_support", "all_required"}, stage, "invalid_derivation")
    for field in (
        "acl_version",
        "content_version",
        "knowledge_base_id",
        "organization_id",
        "principal_id",
        "query",
        "question",
        "source_version",
        "tenant_id",
    ):
        value = fixture[field]
        require(isinstance(value, str) and value.strip() == value and value, stage, f"invalid_{field}")
        require(value.isascii(), stage, f"non_ascii_{field}")
    resources = fixture["resources"]
    require(isinstance(resources, list) and len(resources) == len(EXPECTED_ROLES), stage, "invalid_resources")
    seen_ids: set[str] = set()
    seen_roles: set[str] = set()
    for value in resources:
        require(type(value) is dict and set(value) == RESOURCE_FIXTURE_FIELDS, stage, "invalid_resource")
        role = value["name"]
        resource_id = value["resource_id"]
        content = value["content"]
        require(role in EXPECTED_ROLES and value["type"] == EXPECTED_ROLES[role], stage, "invalid_role")
        require(role not in seen_roles, stage, "duplicate_role")
        require(isinstance(resource_id, str) and RESOURCE_RE.fullmatch(resource_id) is not None, stage, "invalid_resource_id")
        require(resource_id not in seen_ids, stage, "duplicate_resource_id")
        require(isinstance(content, str) and content.strip() == content and content, stage, "invalid_content")
        require(content.isascii() and len(content.encode("utf-8")) <= 4096, stage, "unsafe_content")
        seen_roles.add(role)
        seen_ids.add(resource_id)
    require(seen_roles == set(EXPECTED_ROLES), stage, "incomplete_roles")
    serialized = json.dumps(fixture, sort_keys=True).lower()
    require("${" not in serialized, stage, "environment_placeholder")
    for forbidden in ("api_key", "password", "bearer ", "private_key"):
        require(forbidden not in serialized, stage, "credential_like_content")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def graph_object_id(projection_id: str, resource_id: str) -> str:
    identity = f"{GRAPH_BINDING_VERSION}\0{projection_id}\0{resource_id}"
    return "kg_" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, indent=2).encode("utf-8") + b"\n"


def jsonl_bytes(values: list[dict[str, Any]]) -> bytes:
    return b"".join(
        (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        for value in values
    )


def write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(data)
    path.chmod(0o600)


def resource_handle(fixture: dict[str, Any], resource: dict[str, Any]) -> dict[str, Any]:
    resource_id = resource["resource_id"]
    resource_type = resource["type"]
    projection_id = fixture["projection_id"]
    return {
        "resource_id": resource_id,
        "type": resource_type,
        "tenant_id": fixture["tenant_id"],
        "knowledge_base_id": fixture["knowledge_base_id"],
        "authz_object": f"{resource_type}:{resource_id}",
        "authorization_resource_id": resource_id,
        "content_digest": "sha256:" + sha256_hex(resource["content"].encode("utf-8")),
        "versions": {
            "source": fixture["source_version"],
            "content": fixture["content_version"],
            "acl": fixture["acl_version"],
            "index": "index_" + projection_id,
            "graph": "graph_" + projection_id,
            "projection": projection_id,
        },
        "serving_state": "serving",
    }


def materialize_fixture(fixture_path: Path, workspace: Path, namespace: str) -> MaterializedFixture:
    fixture = load_json_object(fixture_path, "fixture")
    validate_fixture(fixture)
    require(bool(namespace) and namespace.strip() == namespace and namespace.isascii(), "fixture", "invalid_namespace")
    workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
    workspace.chmod(0o700)

    fixture_resources = {value["name"]: value for value in fixture["resources"]}
    resources = {name: resource_handle(fixture, value) for name, value in fixture_resources.items()}
    graph_ids = {
        name: graph_object_id(fixture["projection_id"], resource["resource_id"])
        for name, resource in resources.items()
    }
    graph_rows = sorted(
        (
            {"version": GRAPH_BINDING_VERSION, "graph_object_id": graph_ids[name], "resource": resource}
            for name, resource in resources.items()
        ),
        key=lambda value: value["graph_object_id"],
    )
    source_id = resources["source"]["resource_id"]
    claim_row = {
        "version": GRAPH_BINDING_VERSION,
        "claim": graph_ids["claim"],
        "subject": graph_ids["subject"],
        "predicate_key": fixture["predicate_key"],
        "object": graph_ids["target"],
        "source_document": graph_ids["source"],
        "derivation": fixture["derivation"],
        "provenance": [graph_ids["source"]],
        "subject_resource_id": resources["subject"]["resource_id"],
        "object_resource_id": resources["target"]["resource_id"],
        "source_document_resource_id": source_id,
        "source_version": fixture["source_version"],
        "provenance_resource_ids": [source_id],
        "supports": [
            {
                "support_key": fixture["support_key"],
                "provenance": [graph_ids["source"]],
                "provenance_resource_ids": [source_id],
            }
        ],
    }

    source_text = "\n".join(
        fixture_resources[name]["content"] for name in ("source", "subject", "target")
    ) + "\n"
    write_private(workspace / "sources" / "public-synthetic.txt", source_text.encode("utf-8"))
    write_private(workspace / ".gitignore", b".knote/kag-runtime/\n")
    evidence_paths: dict[str, Path] = {}
    for name, value in fixture_resources.items():
        path = workspace / "evidence" / f"{value['resource_id']}.txt"
        write_private(path, value["content"].encode("utf-8"))
        evidence_paths[name] = path

    projection_id = fixture["projection_id"]
    payloads = {
        "build_report.md": b"# Public synthetic permissioned graph smoke\n",
        "chunks.jsonl": b"",
        "claim_bindings.jsonl": jsonl_bytes([claim_row]),
        "claims.jsonl": b"",
        "documents.jsonl": b"",
        "entities.jsonl": b"",
        "graph_bindings.jsonl": jsonl_bytes(graph_rows),
        "projection.json": json_bytes({"version": projection_id}),
        "relations.jsonl": b"",
        "schema.yaml": b"version: 2\n",
        "summaries.jsonl": b"",
    }
    counts = {
        "build_report.md": 1,
        "claim_bindings.jsonl": 1,
        "graph_bindings.jsonl": len(graph_rows),
        "projection.json": 1,
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
        "projection_id": projection_id,
        "projection_version": projection_id,
        "namespace": namespace,
        "authz_object": "knowledge-base:" + fixture["knowledge_base_id"],
        "authz_version": fixture["acl_version"],
        "graph_binding_contract_version": GRAPH_BINDING_VERSION,
        "source_snapshot": {
            "version": fixture["source_version"],
            "digest": sha256_hex(source_text.encode("utf-8")),
            "document_count": 1,
        },
        "generated_at": "1970-01-01T00:00:00Z",
        "files": descriptors,
        "v1_compatibility": {
            "version": 1,
            "workspace": fixture["knowledge_base_id"],
            "generated_at": "1970-01-01T00:00:00Z",
            "source_count": 1,
        },
    }
    bundle_dir = workspace / "artifacts" / "bundles" / projection_id
    bundle_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    bundle_dir.chmod(0o700)
    for path, data in payloads.items():
        write_private(bundle_dir / path, data)
    manifest_data = json_bytes(manifest)
    write_private(bundle_dir / "manifest.json", manifest_data)
    manifest_digest = sha256_hex(manifest_data)
    write_private(
        workspace / "artifacts" / "current.json",
        json_bytes(
            {
                "version": 2,
                "projection_id": projection_id,
                "projection_version": projection_id,
                "manifest_sha256": manifest_digest,
            }
        ),
    )
    return MaterializedFixture(
        workspace=workspace,
        fixture=fixture,
        resources=resources,
        graph_ids=graph_ids,
        evidence_paths=evidence_paths,
        namespace=namespace,
        manifest_digest=manifest_digest,
    )


def disposable_namespace(prefix: str) -> str:
    require(
        NAMESPACE_PREFIX_RE.fullmatch(prefix) is not None,
        "preflight",
        "invalid_namespace_prefix",
        preflight=True,
    )
    seed = f"{os.getpid()}:{time.time_ns()}".encode("ascii")
    return prefix + sha256_hex(seed)[:12]


def load_fixture_provider(path: Path) -> Any:
    require(path.is_file(), "preflight", "fixture_provider_missing", preflight=True)
    spec = importlib.util.spec_from_file_location("knote_permissioned_graph_live_provider", path)
    require(
        spec is not None and spec.loader is not None,
        "preflight",
        "fixture_provider_unloadable",
        preflight=True,
    )
    module = importlib.util.module_from_spec(spec)
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            spec.loader.exec_module(module)
    except BaseException as exc:
        raise SmokeError("preflight", "fixture_provider_unloadable", exit_code=2) from exc
    return module


def fixture_provider_call(
    provider: Any,
    operation: str,
    context: dict[str, Any],
    stage: str,
    *,
    preflight: bool = False,
) -> Any:
    function = getattr(provider, operation, None)
    require(callable(function), stage, "fixture_provider_capability_missing", preflight=preflight)
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return function(dict(context))
    except BaseException as exc:
        raise SmokeError(
            stage,
            "fixture_provider_call_failed",
            exit_code=2 if preflight else 1,
        ) from exc


def authorization_context(state: MaterializedFixture, model_id: str) -> dict[str, Any]:
    fixture = state.fixture
    return {
        "version": "v1",
        "tenant_id": fixture["tenant_id"],
        "knowledge_base_id": fixture["knowledge_base_id"],
        "principal_id": fixture["principal_id"],
        "session_id": "session_permissioned_graph_smoke",
        "request_id": "request_permissioned_graph_smoke",
        "authorization_model_id": model_id,
        "identity_watermark": "identity_permissioned_graph_smoke_v1",
        "acl_watermark": fixture["acl_version"],
        "consistency": "higher_consistency",
    }


def adapter_call(
    adapter: Path,
    method: str,
    params: dict[str, Any],
    *,
    extra_env: dict[str, str] | None = None,
    timeout: int = 300,
) -> dict[str, Any]:
    stage = method.removeprefix("kag.")
    env = os.environ.copy()
    env.pop("KNOTE_KAG_FAKE", None)
    if extra_env:
        env.update(extra_env)
    request = {"id": f"permissioned_graph_{stage}", "method": method, "params": params}
    try:
        completed = subprocess.run(
            [sys.executable, str(adapter)],
            input=json.dumps(request, sort_keys=True, separators=(",", ":")) + "\n",
            text=True,
            encoding="utf-8",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=adapter.parents[2],
            env=env,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SmokeError(stage, "adapter_process_failed") from exc
    require(completed.returncode == 0, stage, "adapter_process_failed")
    responses: list[dict[str, Any]] = []
    try:
        for line in completed.stdout.splitlines():
            if line.strip():
                value = json.loads(line, object_pairs_hook=unique_object)
                require(type(value) is dict, stage, "invalid_adapter_ndjson")
                responses.append(value)
    except (ValueError, json.JSONDecodeError) as exc:
        raise SmokeError(stage, "invalid_adapter_ndjson") from exc
    require(bool(responses), stage, "empty_adapter_response")
    final = responses[-1]
    if final.get("type") == "error":
        code = final.get("code")
        safe_code = code if isinstance(code, str) and re.fullmatch(r"[a-z0-9_]+", code) else "adapter_error"
        raise SmokeError(stage, safe_code)
    require(final.get("type") == "result" and type(final.get("data")) is dict, stage, "invalid_adapter_result")
    return final["data"]


def assert_real_mode(data: dict[str, Any], stage: str) -> None:
    require(data.get("mode") == "real", stage, "not_real_mode")


def graph_operation(state: MaterializedFixture) -> dict[str, Any]:
    return {
        "version": 1,
        "template": "claim_traversal_v1",
        "parameters": {
            "version": 1,
            "predicate_allowlist_version": 1,
            "resource_kind_allowlist_version": 1,
            "projection_version": state.fixture["projection_id"],
            "identity_version": GRAPH_BINDING_VERSION,
            "start_resource_ids": [state.resources["subject"]["resource_id"]],
            "predicate_keys": [state.fixture["predicate_key"]],
            "resource_kinds": ["entity"],
            "direction": "outbound",
            "fields": [
                "claim_id",
                "derivation_mode",
                "object_id",
                "predicate_key",
                "provenance_ids",
                "source_document_id",
                "source_version",
                "subject_id",
            ],
            "filters": [],
            "order": [
                {"key": "predicate_key", "direction": "ascending", "priority": 0},
                {"key": "object_id", "direction": "ascending", "priority": 1},
                {"key": "claim_id", "direction": "ascending", "priority": 2},
            ],
            "limits": {
                "max_depth": 2,
                "max_frontier_width": MAX_ITEMS,
                "max_candidates_per_hop": MAX_ITEMS,
                "max_total_resources": 128,
                "max_batch_checks": 16,
                "max_wall_clock_millis": 5000,
            },
        },
    }


def exact_load(state: MaterializedFixture, role: str, handle: dict[str, Any]) -> dict[str, Any]:
    stage = "evidence_load"
    require(handle == state.resources[role], stage, "handle_mismatch")
    path = state.evidence_paths[role]
    require(path.is_file() and not path.is_symlink(), stage, "evidence_unavailable")
    try:
        content_bytes = path.read_bytes()
        content = content_bytes.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise SmokeError(stage, "evidence_unavailable") from exc
    require(len(content_bytes) <= 4096 and content.strip() == content, stage, "invalid_evidence")
    require("sha256:" + sha256_hex(content_bytes) == handle["content_digest"], stage, "digest_mismatch")
    return {"resource": handle, "content": content, "citation_handle": "cite-public-synthetic-target"}


def one_candidate(data: dict[str, Any], expected: dict[str, Any], stage: str) -> dict[str, Any]:
    assert_real_mode(data, stage)
    candidates = data.get("candidates")
    require(isinstance(candidates, list) and len(candidates) == 1, stage, "unexpected_candidate_count")
    candidate = candidates[0]
    require(
        type(candidate) is dict
        and set(candidate) == {"resource", "score"}
        and candidate.get("resource") == expected,
        stage,
        "unexpected_candidate",
    )
    return candidate


def attempt_replay(
    capsule: ReplayCapsule,
    authorize: Callable[[dict[str, Any]], bool],
    load: Callable[[dict[str, Any]], Any],
    generate: Callable[[Any], Any],
) -> bool:
    decisions = [authorize(resource) for resource in capsule.resources]
    if not all(decisions):
        return False
    evidence = load(capsule.target)
    generate(evidence)
    return True


def exercise_primitives(
    adapter: Path,
    state: MaterializedFixture,
    common: dict[str, Any],
    authorization: dict[str, Any],
    authorize: Callable[[dict[str, Any]], bool],
    *,
    provider_env: dict[str, str] | None = None,
    retrieve_ready_timeout: float = 0,
) -> tuple[ReplayCapsule, dict[str, int]]:
    timings: dict[str, int] = {}

    def timed(name: str, call: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        started = time.monotonic()
        data = call()
        timings[name] = round((time.monotonic() - started) * 1000)
        return data

    discover = timed(
        "discover",
        lambda: adapter_call(
            adapter,
            "kag.discover",
            {**common, "authorization": authorization, "resource_types": ["claim", "document", "entity"], "limit": MAX_ITEMS},
        ),
    )
    assert_real_mode(discover, "discover")
    discovered = discover.get("resources")
    require(discover.get("complete") is True and isinstance(discovered, list), "discover", "incomplete_catalog")
    require(
        sorted(resource["resource_id"] for resource in discovered)
        == sorted(resource["resource_id"] for resource in state.resources.values()),
        "discover",
        "catalog_mismatch",
    )
    subject = state.resources["subject"]
    require(authorize(subject), "retrieve", "subject_denied")

    deadline = time.monotonic() + retrieve_ready_timeout
    while True:
        retrieve = timed(
            "retrieve",
            lambda: adapter_call(
                adapter,
                "kag.retrieve",
                {
                    **common,
                    "authorization": authorization,
                    "query": state.fixture["query"],
                    "allowed_resources": [subject],
                    "limit": 1,
                },
                extra_env=provider_env,
            ),
        )
        if retrieve.get("candidates") or time.monotonic() >= deadline:
            break
        time.sleep(1)
    subject_candidate = one_candidate(retrieve, subject, "retrieve")

    operation = graph_operation(state)
    first = timed(
        "expand_entity_to_claim",
        lambda: adapter_call(
            adapter,
            "kag.expand",
            {
                **common,
                "authorization": authorization,
                "operation": operation,
                "phase": "entity_to_claim",
                "frontier": [subject_candidate],
                "limit": MAX_ITEMS,
            },
        ),
    )
    claim_candidate = one_candidate(first, state.resources["claim"], "expand_entity_to_claim")
    require(authorize(state.resources["claim"]), "expand_entity_to_claim", "claim_denied")

    second = timed(
        "expand_claim_to_object",
        lambda: adapter_call(
            adapter,
            "kag.expand",
            {
                **common,
                "authorization": authorization,
                "operation": operation,
                "phase": "claim_to_object",
                "frontier": [claim_candidate],
                "limit": MAX_ITEMS,
            },
        ),
    )
    target_candidate = one_candidate(second, state.resources["target"], "expand_claim_to_object")
    target = target_candidate["resource"]
    require(authorize(target), "evidence_load", "target_denied")
    started = time.monotonic()
    evidence = exact_load(state, "target", target)
    timings["evidence_load"] = round((time.monotonic() - started) * 1000)

    path_resources = (subject, state.resources["claim"], target)
    require(all(authorize(resource) for resource in path_resources), "generate", "path_recheck_denied")
    path = {
        "resources": list(path_resources),
        "claim_bindings": [
            {
                "parent_resource_id": subject["resource_id"],
                "claim_resource_id": state.resources["claim"]["resource_id"],
                "object_resource_id": target["resource_id"],
                "predicate_key": state.fixture["predicate_key"],
            }
        ],
    }
    generated = timed(
        "generate",
        lambda: adapter_call(
            adapter,
            "kag.generate",
            {
                **common,
                "authorization": authorization,
                "question": state.fixture["question"],
                "evidence": [evidence],
                "paths": [path],
            },
            extra_env=provider_env,
        ),
    )
    assert_real_mode(generated, "generate")
    require(isinstance(generated.get("answer"), str) and bool(generated["answer"].strip()), "generate", "empty_answer")
    require(generated.get("evidence_resource_ids") == [target["resource_id"]], "generate", "evidence_mismatch")
    require(
        generated.get("citations")
        == [{"handle": evidence["citation_handle"], "resource_id": target["resource_id"]}],
        "generate",
        "citation_mismatch",
    )
    return ReplayCapsule(resources=path_resources, target=target), timings


def self_test(adapter: Path, fixture_path: Path) -> dict[str, Any]:
    namespace = "KnotePermissionedGraphRealSelfTest"
    with tempfile.TemporaryDirectory(prefix="knote-permissioned-graph-selftest-") as first_dir, tempfile.TemporaryDirectory(
        prefix="knote-permissioned-graph-selftest-repeat-"
    ) as second_dir:
        state = materialize_fixture(fixture_path, Path(first_dir), namespace)
        repeated = materialize_fixture(fixture_path, Path(second_dir), namespace)
        require(state.manifest_digest == repeated.manifest_digest, "self_test", "nondeterministic_manifest")
        provider_path = state.workspace / "permissioned_graph_selftest_provider.py"
        write_private(
            provider_path,
            b"class Provider:\n"
            b"    def retrieve(self, request):\n"
            b"        values = request['allowed_graph_object_ids']\n"
            b"        return {'candidates': [{'graph_object_id': values[0], 'score': 1.0}]}\n"
            b"    def generate(self, request):\n"
            b"        return {'answer': 'public synthetic self-test answer'}\n"
            b"def create(context):\n"
            b"    return Provider()\n",
        )
        python_path = str(state.workspace)
        if os.environ.get("PYTHONPATH"):
            python_path += os.pathsep + os.environ["PYTHONPATH"]
        provider_env = {
            "KNOTE_KAG_PERMISSIONED_PROVIDER": "permissioned_graph_selftest_provider:create",
            "PYTHONPATH": python_path,
        }
        allowed = True

        def authorize(_resource: dict[str, Any]) -> bool:
            return allowed

        authorization = authorization_context(state, "model_permissioned_graph_selftest")
        capsule, timings = exercise_primitives(
            adapter,
            state,
            {"workspace": str(state.workspace)},
            authorization,
            authorize,
            provider_env=provider_env,
        )
        allowed = False
        protected_calls = {"load": 0, "generate": 0}

        def blocked_load(_resource: dict[str, Any]) -> None:
            protected_calls["load"] += 1

        def blocked_generate(_evidence: Any) -> None:
            protected_calls["generate"] += 1

        replayed = attempt_replay(capsule, authorize, blocked_load, blocked_generate)
        require(not replayed and protected_calls == {"load": 0, "generate": 0}, "replay_denial", "protected_call_after_deny")
        return {
            "status": "pass",
            "mode": "offline-self-test",
            "fixture": "public-synthetic-v1",
            "resources": len(state.resources),
            "stages": sorted(timings) + ["replay_denial"],
        }


class OpenFGA:
    def __init__(self, binary: Path, api_url: str, expected_cli_version: str, home: Path) -> None:
        self.binary = binary
        self.api_url = api_url.rstrip("/")
        self.expected_cli_version = expected_cli_version
        self.home = home
        self.store_id = ""
        self.model_id = ""

    def _env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["HOME"] = str(self.home)
        token = env.get("KNOTE_OPENFGA_API_TOKEN", "")
        if token:
            env["FGA_API_TOKEN"] = token
        else:
            env.pop("FGA_API_TOKEN", None)
        return env

    def _run(self, arguments: list[str], stage: str, timeout: int = 60) -> str:
        try:
            completed = subprocess.run(
                [str(self.binary), *arguments, "--api-url", self.api_url],
                text=True,
                encoding="utf-8",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self._env(),
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SmokeError(stage, "openfga_cli_failed") from exc
        require(completed.returncode == 0, stage, "openfga_cli_failed")
        return completed.stdout

    def verify_binary(self) -> None:
        require(self.binary.is_file() and os.access(self.binary, os.X_OK), "preflight", "fga_binary_missing", preflight=True)
        try:
            completed = subprocess.run(
                ["go", "version", "-m", str(self.binary)],
                text=True,
                encoding="utf-8",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SmokeError("preflight", "fga_version_unavailable", exit_code=2) from exc
        expected = f"\tmod\t{FGA_MODULE}\t{self.expected_cli_version}"
        require(completed.returncode == 0 and expected in completed.stdout, "preflight", "fga_version_mismatch", preflight=True)

    def create(self, model_path: Path) -> None:
        self.home.mkdir(parents=True, exist_ok=True, mode=0o700)
        name = f"knote-permissioned-graph-real-{os.getpid()}-{int(time.time())}"
        store = self._decode(self._run(["store", "create", "--name", name], "openfga_store"), "openfga_store")
        store_value = store.get("store")
        require(type(store_value) is dict and isinstance(store_value.get("id"), str), "openfga_store", "invalid_store_response")
        self.store_id = store_value["id"]
        model = self._decode(
            self._run(
                [
                    "model",
                    "write",
                    "--store-id",
                    self.store_id,
                    "--file",
                    str(model_path),
                    "--format",
                    "fga",
                ],
                "openfga_model",
            ),
            "openfga_model",
        )
        model_id = model.get("authorization_model_id")
        require(isinstance(model_id, str) and bool(model_id), "openfga_model", "invalid_model_response")
        self.model_id = model_id

    def _decode(self, output: str, stage: str) -> dict[str, Any]:
        try:
            value = json.loads(output, object_pairs_hook=unique_object)
        except (ValueError, json.JSONDecodeError) as exc:
            raise SmokeError(stage, "invalid_openfga_response") from exc
        require(type(value) is dict, stage, "invalid_openfga_response")
        return value

    def write(self, user: str, relation: str, obj: str) -> None:
        self._run(
            [
                "tuple",
                "write",
                "--store-id",
                self.store_id,
                "--model-id",
                self.model_id,
                user,
                relation,
                obj,
            ],
            "openfga_tuples",
        )

    def delete(self, user: str, relation: str, obj: str) -> None:
        self._run(
            [
                "tuple",
                "delete",
                "--store-id",
                self.store_id,
                "--model-id",
                self.model_id,
                user,
                relation,
                obj,
            ],
            "revoke",
        )

    def check(self, user: str, obj: str) -> bool:
        value = self._decode(
            self._run(
                [
                    "query",
                    "check",
                    "--store-id",
                    self.store_id,
                    "--model-id",
                    self.model_id,
                    "--consistency",
                    "HIGHER_CONSISTENCY",
                    user,
                    "can_view",
                    obj,
                ],
                "openfga_check",
            ),
            "openfga_check",
        )
        require(type(value.get("allowed")) is bool, "openfga_check", "invalid_check_response")
        return value["allowed"]

    def cleanup(self) -> None:
        if not self.store_id:
            return
        self._run(
            ["store", "delete", "--store-id", self.store_id, "--force"],
            "openfga_cleanup",
        )
        self.store_id = ""


def validate_endpoint(value: str, stage: str) -> None:
    parsed = urllib.parse.urlsplit(value)
    require(parsed.scheme in {"http", "https"} and bool(parsed.hostname), stage, "invalid_endpoint", preflight=True)
    require(parsed.username is None and parsed.password is None and not parsed.query and not parsed.fragment, stage, "unsafe_endpoint", preflight=True)
    if parsed.scheme == "http":
        require(parsed.hostname in {"127.0.0.1", "localhost", "::1"}, stage, "insecure_remote_endpoint", preflight=True)


def openfga_tuples(state: MaterializedFixture) -> list[tuple[str, str, str]]:
    fixture = state.fixture
    principal = "user:" + fixture["principal_id"]
    organization = "organization:" + fixture["organization_id"]
    knowledge_base = "knowledge_base:" + fixture["knowledge_base_id"]
    source = "document:" + state.resources["source"]["resource_id"]
    subject = "entity:" + state.resources["subject"]["resource_id"]
    target = "entity:" + state.resources["target"]["resource_id"]
    claim = "claim:" + state.resources["claim"]["resource_id"]
    return [
        (principal, "member", organization),
        (organization, "organization", knowledge_base),
        (principal, "viewer", knowledge_base),
        (organization, "organization", source),
        (knowledge_base, "parent", source),
        (organization, "organization", subject),
        (source, "source_document", subject),
        (organization, "organization", target),
        (source, "source_document", target),
        (organization, "organization", claim),
        (source, "source_document", claim),
        (subject, "subject", claim),
        (target, "object", claim),
    ]


def run_live(args: argparse.Namespace) -> dict[str, Any]:
    required = {
        "workspace": args.workspace,
        "kag_host": args.kag_host,
        "fga_bin": args.fga_bin,
        "openfga_api_url": args.openfga_api_url,
        "openfga_server_version": args.openfga_server_version,
        "openspg_server_version": args.openspg_server_version,
        "openfga_version_verification": args.openfga_version_verification,
        "openspg_version_verification": args.openspg_version_verification,
    }
    missing = sorted(name for name, value in required.items() if not value)
    require(not missing, "preflight", "missing_required_configuration", preflight=True)
    validate_endpoint(args.kag_host, "preflight")
    validate_endpoint(args.openfga_api_url, "preflight")
    require(sys.version_info >= (3, 11), "preflight", "python_version_unsupported", preflight=True)

    namespace = disposable_namespace(args.kag_namespace_prefix)
    state = materialize_fixture(args.fixture, Path(args.workspace), namespace)
    require(
        re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.provider.stem) is not None,
        "preflight",
        "invalid_fixture_provider_name",
        preflight=True,
    )
    provider = load_fixture_provider(args.provider.resolve())
    versions = fixture_provider_call(
        provider,
        "runtime_versions",
        {},
        "preflight",
        preflight=True,
    )
    require(type(versions) is dict, "preflight", "invalid_runtime_versions", preflight=True)
    require(
        versions.get("kag") == args.expected_kag_version,
        "preflight",
        "kag_version_mismatch",
        preflight=True,
    )
    require(
        versions.get("knext") == args.expected_knext_version,
        "preflight",
        "knext_version_mismatch",
        preflight=True,
    )
    try:
        health = adapter_call(
            args.adapter,
            "kag.health",
            {"workspace": str(state.workspace), "host": args.kag_host},
            timeout=15,
        )
    except SmokeError as exc:
        raise SmokeError("preflight", "kag_service_unavailable", exit_code=2) from exc
    assert_real_mode(health, "preflight")
    kag_version = str(health.get("version") or "")
    require(kag_version.lstrip("v") == args.expected_kag_version.lstrip("v"), "preflight", "kag_version_mismatch", preflight=True)

    fga = OpenFGA(Path(args.fga_bin), args.openfga_api_url, args.expected_fga_cli_version, state.workspace / ".fga-home")
    fga.verify_binary()
    failure: SmokeError | None = None
    report: dict[str, Any] | None = None
    openspg_project_id = ""
    openspg_context: dict[str, Any] = {
        "workspace": str(state.workspace),
        "host": args.kag_host,
        "namespace": namespace,
    }
    try:
        fga.create(args.model)
        for user, relation, obj in openfga_tuples(state):
            fga.write(user, relation, obj)

        principal = "user:" + state.fixture["principal_id"]

        def authorize(resource: dict[str, Any]) -> bool:
            return fga.check(principal, resource["authz_object"])

        require(not fga.check("user:unknown", state.resources["subject"]["authz_object"]), "openfga_check", "unknown_principal_allowed")
        project_started = time.monotonic()
        project_value = fixture_provider_call(
            provider,
            "create_disposable_project",
            openspg_context,
            "openspg_project",
        )
        require(isinstance(project_value, str) and project_value.isdigit(), "openspg_project", "invalid_project_id")
        openspg_project_id = project_value
        openspg_context["project_id"] = openspg_project_id
        project_duration = round((time.monotonic() - project_started) * 1000)

        setup_started = time.monotonic()
        setup = fixture_provider_call(
            provider,
            "sync_schema_upsert_and_probe",
            openspg_context,
            "openspg_setup",
        )
        require(
            setup == {"vertices": 2, "edges": 1, "reasoner_rows_minimum": 1},
            "openspg_setup",
            "incomplete_graph_fixture",
        )
        setup_duration = round((time.monotonic() - setup_started) * 1000)

        common = {
            "workspace": str(state.workspace),
            "host": args.kag_host,
            "project_id": openspg_project_id,
            "namespace": state.namespace,
            "language": args.kag_language,
        }
        python_path = str(args.provider.resolve().parent)
        if os.environ.get("PYTHONPATH"):
            python_path += os.pathsep + os.environ["PYTHONPATH"]
        provider_env = {
            "KNOTE_KAG_PERMISSIONED_PROVIDER": f"{args.provider.stem}:create",
            "PYTHONPATH": python_path,
        }
        authorization = authorization_context(state, fga.model_id)
        capsule, timings = exercise_primitives(
            args.adapter,
            state,
            common,
            authorization,
            authorize,
            provider_env=provider_env,
            retrieve_ready_timeout=args.index_ready_timeout,
        )
        timings["openspg_project"] = project_duration
        timings["openspg_setup"] = setup_duration

        revoke_started = time.monotonic()
        fga.delete(principal, "viewer", "knowledge_base:" + state.fixture["knowledge_base_id"])
        deadline = revoke_started + args.revocation_timeout
        while authorize(state.resources["subject"]) and time.monotonic() < deadline:
            time.sleep(0.05)
        require(not any(authorize(resource) for resource in capsule.resources), "revoke", "revocation_not_observed")
        timings["revoke"] = round((time.monotonic() - revoke_started) * 1000)
        protected_calls = {"load": 0, "generate": 0}

        def blocked_load(_resource: dict[str, Any]) -> None:
            protected_calls["load"] += 1

        def blocked_generate(_evidence: Any) -> None:
            protected_calls["generate"] += 1

        replayed = attempt_replay(capsule, authorize, blocked_load, blocked_generate)
        require(not replayed and protected_calls == {"load": 0, "generate": 0}, "replay_denial", "protected_call_after_revoke")
        timings["replay_denial"] = 0
        report = {
            "status": "pass",
            "mode": "live",
            "fixture": "public-synthetic-v1",
            "resources": len(state.resources),
            "stages": [
                "openspg_project",
                "openspg_setup",
                "discover",
                "retrieve",
                "expand_entity_to_claim",
                "expand_claim_to_object",
                "evidence_load",
                "generate",
                "revoke",
                "replay_denial",
            ],
            "durations_ms": {name: timings[name] for name in sorted(timings)},
            "versions": {
                "fga_cli": args.expected_fga_cli_version,
                "openfga_server": args.openfga_server_version,
                "openspg_server": args.openspg_server_version,
                "knext": versions["knext"],
                "openspg_kag": kag_version,
                "python": ".".join(str(value) for value in sys.version_info[:3]),
            },
            "version_verification": {
                "openfga_server": args.openfga_version_verification,
                "openspg_server": args.openspg_version_verification,
            },
        }
    except SmokeError as exc:
        failure = exc
    finally:
        if openspg_project_id and not args.disposable_openspg_stack:
            try:
                fixture_provider_call(
                    provider,
                    "delete_disposable_project",
                    openspg_context,
                    "openspg_cleanup",
                )
                openspg_project_id = ""
            except SmokeError as cleanup_error:
                failure = cleanup_error
        try:
            fga.cleanup()
        except SmokeError as cleanup_error:
            failure = cleanup_error
    if failure is not None:
        raise failure
    require(report is not None, "internal", "missing_report")
    return report


def parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[2]
    value = argparse.ArgumentParser()
    mode = value.add_mutually_exclusive_group(required=True)
    mode.add_argument("--self-test", action="store_true")
    mode.add_argument("--live", action="store_true")
    value.add_argument("--adapter", type=Path, default=root / "adapters" / "kag" / "knote_kag_adapter.py")
    value.add_argument("--fixture", type=Path, default=root / "tests" / "fixtures" / "permissioned-graph-real" / "fixture.json")
    value.add_argument(
        "--provider",
        type=Path,
        default=root / "tests" / "fixtures" / "permissioned-graph-real" / "permissioned_graph_provider.py",
    )
    value.add_argument("--model", type=Path, default=root / "internal" / "authz" / "model" / "authorization.fga")
    value.add_argument("--workspace")
    value.add_argument("--kag-host")
    value.add_argument("--kag-namespace-prefix", default="KnotePermissionedGraphReal")
    value.add_argument("--kag-language", default="en")
    value.add_argument("--fga-bin")
    value.add_argument("--openfga-api-url")
    value.add_argument("--expected-fga-cli-version", default="v0.7.17")
    value.add_argument("--expected-kag-version", default="0.8.0")
    value.add_argument("--expected-knext-version", default="0.8.0")
    value.add_argument("--openfga-server-version")
    value.add_argument("--openspg-server-version")
    value.add_argument(
        "--openfga-version-verification",
        choices=("repository-pinned-image-digest", "caller-declared"),
    )
    value.add_argument(
        "--openspg-version-verification",
        choices=("repository-pinned-image-digest", "caller-declared"),
    )
    value.add_argument("--disposable-openspg-stack", action="store_true")
    value.add_argument("--index-ready-timeout", type=float, default=30)
    value.add_argument("--revocation-timeout", type=float, default=10)
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        require(args.adapter.is_file(), "preflight", "adapter_missing", preflight=True)
        require(args.fixture.is_file(), "preflight", "fixture_missing", preflight=True)
        require(args.model.is_file(), "preflight", "authorization_model_missing", preflight=True)
        report = self_test(args.adapter.resolve(), args.fixture.resolve()) if args.self_test else run_live(args)
        emit_safe(report)
        return 0
    except SmokeError as exc:
        emit_safe({"status": "fail", "stage": exc.stage, "code": exc.code})
        return exc.exit_code
    except KeyboardInterrupt:
        emit_safe({"status": "fail", "stage": "interrupted", "code": "cancelled"})
        return 130
    except BaseException as exc:  # Keep unexpected provider/content details out of retained logs.
        emit_safe(
            {
                "status": "fail",
                "stage": "internal",
                "code": "unexpected_exception",
                "exception_type": type(exc).__name__,
            }
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
