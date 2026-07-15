"""Sanitized low-level OpenSPG/KAG provider for the opt-in real smoke."""

from __future__ import annotations

import json
import re
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


NAMESPACE_RE = re.compile(r"[A-Za-z][A-Za-z0-9]{0,47}\Z")
GRAPH_ID_RE = re.compile(r"kg_[0-9a-f]{32}\Z")
RESOURCE_ID_RE = re.compile(r"res_[0-9a-f]{32}\Z")
REASONER_DSL = (
    "MATCH (s:{namespace}.Service)-[p:owns]->(o:{namespace}.Checklist) "
    "WHERE s.id in $sid RETURN s,p,o,s.id,o.id"
)
PROJECT_CONFIG = {"vectorizer": {"type": "mock", "vector_dimensions": 8}}


class FixtureProviderError(Exception):
    pass


def _require(condition: bool) -> None:
    if not condition:
        raise FixtureProviderError("invalid sanitized fixture state")


def _plain_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    _require(type(value) is dict)
    return value


def _context(value: dict[str, Any], *, project: bool) -> dict[str, Any]:
    _require(type(value) is dict)
    workspace = Path(str(value.get("workspace") or "")).resolve()
    host = str(value.get("host") or "").rstrip("/")
    namespace = str(value.get("namespace") or "")
    parsed = urllib.parse.urlsplit(host)
    _require(workspace.is_dir())
    _require(parsed.scheme in {"http", "https"} and bool(parsed.hostname))
    _require(parsed.username is None and parsed.password is None)
    _require(parsed.query == "" and parsed.fragment == "")
    _require(NAMESPACE_RE.fullmatch(namespace) is not None)
    result: dict[str, Any] = {
        "workspace": workspace,
        "host": host,
        "namespace": namespace,
    }
    if project:
        project_id = str(value.get("project_id") or "")
        _require(project_id.isdigit() and int(project_id) > 0)
        result["project_id"] = int(project_id)
    return result


def _graph_fixture(workspace: Path) -> dict[str, str]:
    current = _plain_object(workspace / "artifacts" / "current.json")
    projection_id = current.get("projection_id")
    _require(isinstance(projection_id, str))
    bundle = workspace / "artifacts" / "bundles" / projection_id
    lines = (bundle / "claim_bindings.jsonl").read_text(encoding="utf-8").splitlines()
    _require(len(lines) == 1)
    claim = json.loads(lines[0])
    _require(type(claim) is dict)
    graph_rows = [
        json.loads(line)
        for line in (bundle / "graph_bindings.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    resource_by_graph_id = {
        row.get("graph_object_id"): row.get("resource", {}).get("resource_id")
        for row in graph_rows
        if type(row) is dict and type(row.get("resource")) is dict
    }
    values = {
        "service": claim.get("subject"),
        "checklist": claim.get("object"),
        "service_resource": claim.get("subject_resource_id"),
        "checklist_resource": claim.get("object_resource_id"),
        "claim_resource": resource_by_graph_id.get(claim.get("claim")),
    }
    _require(
        all(
            isinstance(values[name], str) and GRAPH_ID_RE.fullmatch(values[name])
            for name in ("service", "checklist")
        )
    )
    _require(
        all(
            isinstance(values[name], str) and RESOURCE_ID_RE.fullmatch(values[name])
            for name in ("service_resource", "checklist_resource", "claim_resource")
        )
    )
    return values


def _imports() -> dict[str, Any]:
    import kag
    import knext
    from knext.common.rest import ApiClient, Configuration
    from knext.graph import EdgeRecordInstance, UpsertEdgeRequest, UpsertVertexRequest, VertexRecordInstance
    from knext.graph.rest import GraphApi
    from knext.project.client import ProjectClient
    from knext.reasoner.client import ReasonerClient
    from knext.schema.marklang.schema_ml import SPGSchemaMarkLang

    return {
        "ApiClient": ApiClient,
        "Configuration": Configuration,
        "EdgeRecordInstance": EdgeRecordInstance,
        "GraphApi": GraphApi,
        "ProjectClient": ProjectClient,
        "ReasonerClient": ReasonerClient,
        "SPGSchemaMarkLang": SPGSchemaMarkLang,
        "UpsertEdgeRequest": UpsertEdgeRequest,
        "UpsertVertexRequest": UpsertVertexRequest,
        "VertexRecordInstance": VertexRecordInstance,
        "kag_version": str(kag.__version__),
        "knext_version": str(knext.__version__),
    }


def runtime_versions(_value: dict[str, Any] | None = None) -> dict[str, str]:
    imports = _imports()
    return {
        "kag": imports["kag_version"],
        "knext": imports["knext_version"],
    }


def create_disposable_project(value: dict[str, Any]) -> str:
    context = _context(value, project=False)
    imports = _imports()
    client = imports["ProjectClient"](host_addr=context["host"])
    project = client.create(
        name=context["namespace"],
        namespace=context["namespace"],
        config=PROJECT_CONFIG,
    )
    project_id = str(getattr(project, "id", ""))
    _require(project_id.isdigit() and int(project_id) > 0)
    return project_id


def _schema(namespace: str) -> str:
    return f"""namespace {namespace}

Service(Service): EntityType
    properties:
        displayName(displayName): Text
            index: Text
    relations:
        owns(owns): Checklist

Checklist(Checklist): EntityType
    properties:
        displayName(displayName): Text
            index: Text
"""


def _reasoner_probe(context: dict[str, Any], graph_ids: dict[str, str], imports: dict[str, Any]) -> None:
    reasoner = imports["ReasonerClient"](
        host_addr=context["host"],
        project_id=context["project_id"],
        namespace=context["namespace"],
    )
    properties = reasoner.query_node(
        f"{context['namespace']}.Service",
        graph_ids["service"],
    )
    _require(isinstance(properties, dict) and bool(properties))
    response = reasoner.syn_execute(
        REASONER_DSL.format(namespace=context["namespace"]),
        sid=json.dumps([graph_ids["service"]], separators=(",", ":")),
    )
    task = getattr(response, "task", None)
    table = getattr(task, "result_table_result", None)
    rows = getattr(table, "rows", None)
    _require(getattr(task, "status", None) == "FINISH")
    _require(isinstance(rows, list) and len(rows) >= 1)


def sync_schema_upsert_and_probe(value: dict[str, Any]) -> dict[str, int]:
    context = _context(value, project=True)
    graph_ids = _graph_fixture(context["workspace"])
    imports = _imports()
    imports["SPGSchemaMarkLang"](
        filename="",
        host_addr=context["host"],
        project_id=context["project_id"],
        script_data_str=_schema(context["namespace"]),
    ).sync_schema()

    graph_api = imports["GraphApi"](
        api_client=imports["ApiClient"](
            configuration=imports["Configuration"](host=context["host"])
        )
    )
    service = imports["VertexRecordInstance"](
        type=f"{context['namespace']}.Service",
        id=graph_ids["service"],
        properties={"displayName": "Service Alpha"},
        vectors={},
    )
    checklist = imports["VertexRecordInstance"](
        type=f"{context['namespace']}.Checklist",
        id=graph_ids["checklist"],
        properties={"displayName": "Checklist Beta"},
        vectors={},
    )
    graph_api.graph_upsert_vertex_post(
        upsert_vertex_request=imports["UpsertVertexRequest"](
            project_id=context["project_id"],
            vertices=[service],
        )
    )
    graph_api.graph_upsert_vertex_post(
        upsert_vertex_request=imports["UpsertVertexRequest"](
            project_id=context["project_id"],
            vertices=[checklist],
        )
    )
    edge = imports["EdgeRecordInstance"](
        src_type=f"{context['namespace']}.Service",
        src_id=graph_ids["service"],
        dst_type=f"{context['namespace']}.Checklist",
        dst_id=graph_ids["checklist"],
        label="owns",
        properties={},
    )
    graph_api.graph_upsert_edge_post(
        upsert_edge_request=imports["UpsertEdgeRequest"](
            project_id=context["project_id"],
            upsert_adjacent_vertices=False,
            edges=[edge],
        )
    )
    deadline = time.monotonic() + 30
    while True:
        try:
            _reasoner_probe(context, graph_ids, imports)
            break
        except BaseException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(1)
    return {"vertices": 2, "edges": 1, "reasoner_rows_minimum": 1}


def delete_disposable_project(value: dict[str, Any]) -> None:
    context = _context(value, project=True)
    query = urllib.parse.urlencode({"projectId": context["project_id"]})
    request = urllib.request.Request(
        f"{context['host']}/project/api/delete?{query}",
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        _require(200 <= response.status < 300)
        payload = response.read((1 << 20) + 1)
    _require(len(payload) <= 1 << 20)
    result = json.loads(payload)
    _require(type(result) is dict and result.get("success") is True)


class Provider:
    def __init__(self, value: dict[str, Any]) -> None:
        self.context = _context(value, project=True)
        self.graph_ids = _graph_fixture(self.context["workspace"])

    def _probe(self) -> None:
        _reasoner_probe(self.context, self.graph_ids, _imports())

    def retrieve(self, request: dict[str, Any]) -> dict[str, Any]:
        allowed = request.get("allowed_graph_object_ids")
        _require(allowed == [self.graph_ids["service"]])
        self._probe()
        return {
            "candidates": [
                {"graph_object_id": self.graph_ids["service"], "score": 1.0}
            ]
        }

    def generate(self, request: dict[str, Any]) -> dict[str, str]:
        evidence = request.get("evidence")
        _require(isinstance(evidence, list) and len(evidence) == 1)
        item = evidence[0]
        _require(type(item) is dict)
        resource = item.get("resource")
        _require(
            type(resource) is dict
            and resource.get("resource_id") == self.graph_ids["checklist_resource"]
        )
        evidence_path = (
            self.context["workspace"]
            / "evidence"
            / f"{self.graph_ids['checklist_resource']}.txt"
        )
        _require(item.get("content") == evidence_path.read_text(encoding="utf-8"))
        _require(item.get("citation_handle") == "cite-public-synthetic-target")
        paths = request.get("paths")
        _require(isinstance(paths, list) and len(paths) == 1)
        resources = paths[0].get("resources") if type(paths[0]) is dict else None
        _require(
            isinstance(resources, list)
            and all(type(resource_value) is dict for resource_value in resources)
            and [resource_value.get("resource_id") for resource_value in resources]
            == [
                self.graph_ids["service_resource"],
                self.graph_ids["claim_resource"],
                self.graph_ids["checklist_resource"],
            ]
        )
        self._probe()
        return {"answer": "Checklist Beta is connected to Service Alpha."}


def create(context: dict[str, Any]) -> Provider:
    return Provider(context)
