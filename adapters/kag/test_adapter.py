from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import importlib.util
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
ADAPTER_PATH = ROOT / "adapters" / "kag" / "knote_kag_adapter.py"
SPEC = importlib.util.spec_from_file_location("knote_kag_adapter", ADAPTER_PATH)
adapter = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(adapter)


def call_adapter(
    request: object,
    *,
    fake: bool = True,
    stage_spy: bool = False,
    extra_env: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], list[dict[str, object]]]:
    env = os.environ.copy()
    if fake:
        env["KNOTE_KAG_FAKE"] = "1"
    else:
        env.pop("KNOTE_KAG_FAKE", None)
    if stage_spy:
        env[adapter.TEST_STAGE_SPY_ENV] = "1"
    else:
        env.pop(adapter.TEST_STAGE_SPY_ENV, None)
    env.pop(adapter.TEST_DELAY_MS_ENV, None)
    if extra_env:
        env.update(extra_env)
    proc = subprocess.run(
        [sys.executable, str(ADAPTER_PATH)],
        input=json.dumps(request) + "\n",
        text=True,
        capture_output=True,
        cwd=ROOT,
        env=env,
        check=True,
    )
    return proc, [json.loads(line) for line in proc.stdout.splitlines()]


def candidate_resource_id(candidate: dict[str, object]) -> str:
    return candidate["resource"]["resource_id"]


def fake_resource_handle(resource_id: str) -> dict[str, object]:
    return adapter.copy_fake_candidate(resource_id)["resource"]


def authorization_context(**overrides: object) -> dict[str, object]:
    authorization: dict[str, object] = {
        "version": "v1",
        "tenant_id": "tenant_fake",
        "knowledge_base_id": "kb_fake",
        "principal_id": "principal_fake",
        "session_id": "session_fake",
        "request_id": "request_fake",
        "authorization_model_id": "model_fake",
        "identity_watermark": "identity_fake",
        "acl_watermark": "acl_fake",
        "consistency": "higher_consistency",
    }
    authorization.update(overrides)
    return authorization


def authorized_params(**params: object) -> dict[str, object]:
    return {"authorization": authorization_context(), **params}


def initialize_checkout_projection(
    workspace: Path, namespace: str = "projection-one"
) -> tuple[Path, Path, str]:
    projection_id = "prj_" + "a" * 32
    base = workspace / ".knote" / "kag_config.yaml"
    base.parent.mkdir(parents=True)
    base.write_text(
        "project:\n  namespace: shared\n  checkpoint_path: shared/ckpt\n"
        "kag_solver_pipeline:\n  type: custom_solver\n",
        encoding="utf-8",
    )
    manifest = {
        "version": 2,
        "projection_id": projection_id,
        "projection_version": projection_id,
        "namespace": namespace,
    }
    manifest_path = workspace / "artifacts" / "bundles" / projection_id / "manifest.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_data = json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    manifest_path.write_bytes(manifest_data)
    current = {
        "version": 2,
        "projection_id": projection_id,
        "projection_version": projection_id,
        "manifest_sha256": hashlib.sha256(manifest_data).hexdigest(),
    }
    (workspace / "artifacts" / "current.json").write_text(
        json.dumps(current, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    (workspace / ".gitignore").write_text(".knote/kag-runtime/\n", encoding="utf-8")
    subprocess.run(["git", "init"], cwd=workspace, text=True, capture_output=True, check=True)
    subprocess.run(["git", "add", "."], cwd=workspace, text=True, capture_output=True, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=knote-test",
            "-c",
            "user.email=knote-test@example.invalid",
            "commit",
            "-m",
            "checkout fixture",
        ],
        cwd=workspace,
        text=True,
        capture_output=True,
        check=True,
    )
    runtime = (workspace / ".knote" / "kag-runtime" / "projections" / namespace).resolve()
    return base, runtime, projection_id


class AdapterTest(unittest.TestCase):
    def test_fake_health(self) -> None:
        env = os.environ.copy()
        env["KNOTE_KAG_FAKE"] = "1"
        req = {"id": "1", "method": "kag.health", "params": {"workspace": str(Path.cwd())}}
        proc = subprocess.run(
            [sys.executable, "adapters/kag/knote_kag_adapter.py"],
            input=json.dumps(req) + "\n",
            text=True,
            capture_output=True,
            cwd=ROOT,
            env=env,
            check=True,
        )
        lines = [json.loads(line) for line in proc.stdout.splitlines()]
        self.assertEqual(lines[-1]["type"], "result")
        self.assertEqual(lines[-1]["data"]["mode"], "fake")

    def test_fake_retrieve_contract_is_deterministic_and_body_free(self) -> None:
        request = {
            "id": "retrieve-1",
            "method": "kag.retrieve",
            "params": authorized_params(query="What is knote?", limit=2),
        }

        _, first_lines = call_adapter(request)
        _, second_lines = call_adapter(request)

        first = first_lines[-1]
        second = second_lines[-1]
        self.assertEqual(first, second)
        self.assertEqual(first["type"], "result")
        data = first["data"]
        self.assertEqual(set(data), {"mode", "candidates"})
        self.assertEqual(data["mode"], "fake")
        self.assertEqual(
            [candidate_resource_id(candidate) for candidate in data["candidates"]],
            [adapter.FAKE_INTRO_ID, adapter.FAKE_DENIED_CANARY_ID],
        )
        for candidate in data["candidates"]:
            self.assertEqual(set(candidate), adapter.CANDIDATE_FIELDS)
            resource = candidate["resource"]
            self.assertEqual(set(resource), adapter.RESOURCE_FIELDS)
            self.assertEqual(set(resource["versions"]), adapter.RESOURCE_VERSION_FIELDS)
            self.assertRegex(resource["resource_id"], r"^res_[0-9a-f]{32}$")
            self.assertEqual(resource["authorization_resource_id"], resource["resource_id"])
            self.assertRegex(resource["content_digest"], r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(resource["serving_state"], "serving")
            self.assertTrue(all(resource["versions"].values()))
            self.assertTrue({"body", "text", "title", "path"}.isdisjoint(resource))

    def test_fake_expand_contract_contains_only_handles_and_edges(self) -> None:
        _, retrieve_lines = call_adapter(
            {
                "id": "retrieve",
                "method": "kag.retrieve",
                "params": authorized_params(query="What is knote?"),
            }
        )
        intro = next(
            candidate
            for candidate in retrieve_lines[-1]["data"]["candidates"]
            if candidate_resource_id(candidate) == adapter.FAKE_INTRO_ID
        )

        _, lines = call_adapter(
            {
                "id": "expand",
                "method": "kag.expand",
                "params": authorized_params(frontier=[intro], limit=2),
            }
        )

        response = lines[-1]
        self.assertEqual(response["type"], "result")
        data = response["data"]
        self.assertEqual(set(data), {"mode", "candidates", "expansions"})
        self.assertEqual(
            [candidate_resource_id(candidate) for candidate in data["candidates"]],
            [adapter.FAKE_LOCAL_FIRST_ID, adapter.FAKE_DENIED_FRONTIER_ID],
        )
        for candidate in data["candidates"]:
            self.assertEqual(set(candidate), adapter.CANDIDATE_FIELDS)
            self.assertEqual(set(candidate["resource"]), adapter.RESOURCE_FIELDS)
            self.assertEqual(set(candidate["resource"]["versions"]), adapter.RESOURCE_VERSION_FIELDS)
        for expansion in data["expansions"]:
            self.assertEqual(set(expansion), {"from_resource_id", "to_resource_id", "hop"})
            self.assertEqual(expansion["from_resource_id"], adapter.FAKE_INTRO_ID)
            self.assertEqual(expansion["hop"], 1)
        self.assertNotIn("body", json.dumps(data))
        self.assertNotIn("relation", json.dumps(data))

    def test_fake_generate_contract_uses_only_explicit_evidence(self) -> None:
        evidence = [
            {
                "resource": fake_resource_handle(adapter.FAKE_INTRO_ID),
                "content": "knote is local-first.",
                "citation_handle": "cite_intro",
            },
            {
                "resource": fake_resource_handle(adapter.FAKE_LOCAL_FIRST_ID),
                "content": "Its runtime can authorize graph stages before generation.",
                "citation_handle": "cite_runtime",
            },
        ]

        _, lines = call_adapter(
            {
                "id": "generate",
                "method": "kag.generate",
                "params": authorized_params(question="What is knote?", evidence=evidence),
            }
        )

        response = lines[-1]
        self.assertEqual(response["type"], "result")
        data = response["data"]
        self.assertEqual(
            set(data),
            {"mode", "answer", "citations", "evidence_resource_ids", "trace"},
        )
        self.assertEqual(
            data["citations"],
            [
                {"handle": "cite_intro", "resource_id": adapter.FAKE_INTRO_ID},
                {"handle": "cite_runtime", "resource_id": adapter.FAKE_LOCAL_FIRST_ID},
            ],
        )
        self.assertEqual(
            data["evidence_resource_ids"],
            [adapter.FAKE_INTRO_ID, adapter.FAKE_LOCAL_FIRST_ID],
        )
        self.assertEqual(
            data["trace"],
            {"resource_ids": [adapter.FAKE_INTRO_ID, adapter.FAKE_LOCAL_FIRST_ID], "count": 2},
        )
        self.assertIn("knote is local-first.", data["answer"])
        self.assertIn("Its runtime can authorize graph stages before generation.", data["answer"])

    def test_validate_evidence_preserves_whitespace_for_digest(self) -> None:
        content = "  authorized body with boundary whitespace  \n"
        resource = fake_resource_handle(adapter.FAKE_INTRO_ID)
        resource["content_digest"] = "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest()

        validated = adapter.validate_evidence(
            {"resource": resource, "content": content, "citation_handle": "cite-whitespace"},
            "evidence[0]",
        )

        self.assertEqual(validated["content"], content)

    def test_authorization_context_is_exact_and_fail_closed(self) -> None:
        accepted = authorization_context(agent_id="agent_fake", task_id="task_fake")
        _, accepted_lines = call_adapter(
            {
                "id": "accepted",
                "method": "kag.retrieve",
                "params": {"authorization": accepted, "query": "q", "limit": 1},
            }
        )
        self.assertEqual(accepted_lines[-1]["type"], "result")

        invalid_authorizations: list[tuple[dict[str, object], str]] = []
        missing = authorization_context()
        missing.pop("principal_id")
        invalid_authorizations.append((missing, "missing principal_id"))
        invalid_authorizations.extend(
            [
                (authorization_context(unexpected="value"), "unexpected unexpected"),
                (authorization_context(version="v2"), "authorization.version must be v1"),
                (
                    authorization_context(consistency="eventual"),
                    "authorization.consistency is unsupported",
                ),
                (
                    authorization_context(principal_id=" principal_fake"),
                    "authorization.principal_id contains leading or trailing whitespace",
                ),
                (
                    authorization_context(request_id="request\ninvalid"),
                    "authorization.request_id contains control characters",
                ),
            ]
        )
        for authorization, expected_error in invalid_authorizations:
            with self.subTest(expected_error=expected_error):
                _, lines = call_adapter(
                    {
                        "id": "invalid-auth",
                        "method": "kag.retrieve",
                        "params": {"authorization": authorization, "query": "q"},
                    }
                )
                response = lines[-1]
                self.assertEqual(response["type"], "error")
                self.assertEqual(response["code"], "invalid_request")
                self.assertIn(expected_error, response["error"])

    def test_fake_primitives_reject_resources_outside_authorization_scope(self) -> None:
        candidate = adapter.copy_fake_candidate(adapter.FAKE_INTRO_ID)
        outside_tenant = {
            **candidate,
            "resource": {**candidate["resource"], "tenant_id": "tenant_other"},
        }
        evidence_resource = fake_resource_handle(adapter.FAKE_INTRO_ID)
        outside_knowledge_base = {
            **evidence_resource,
            "knowledge_base_id": "kb_other",
        }
        evidence = {
            "resource": outside_knowledge_base,
            "content": adapter.FAKE_CONTENT_BY_ID[adapter.FAKE_INTRO_ID],
            "citation_handle": "cite_intro",
        }
        cases = [
            (
                {
                    "id": "retrieve-scope",
                    "method": "kag.retrieve",
                    "params": {
                        "authorization": authorization_context(tenant_id="tenant_other"),
                        "query": "q",
                    },
                },
                "outside authorization tenant_id",
            ),
            (
                {
                    "id": "expand-scope",
                    "method": "kag.expand",
                    "params": authorized_params(frontier=[outside_tenant]),
                },
                "outside authorization tenant_id",
            ),
            (
                {
                    "id": "generate-scope",
                    "method": "kag.generate",
                    "params": authorized_params(question="q", evidence=[evidence]),
                },
                "outside authorization knowledge_base_id",
            ),
        ]
        for request, expected_error in cases:
            with self.subTest(method=request["method"]):
                _, lines = call_adapter(request)
                response = lines[-1]
                self.assertEqual(response["type"], "error")
                self.assertEqual(response["code"], "invalid_request")
                self.assertIn(expected_error, response["error"])

    def test_denied_candidates_are_absent_from_later_hops_and_generation(self) -> None:
        denied_candidate_id = adapter.FAKE_DENIED_CANARY_ID
        denied_candidate_body = adapter.FAKE_CONTENT_BY_ID[denied_candidate_id]
        denied_frontier_id = adapter.FAKE_DENIED_FRONTIER_ID
        denied_frontier_body = adapter.FAKE_CONTENT_BY_ID[denied_frontier_id]
        observed_processes: list[subprocess.CompletedProcess[str]] = []

        retrieve_proc, retrieve_lines = call_adapter(
            {
                "id": "r",
                "method": "kag.retrieve",
                "params": authorized_params(query="What is knote?"),
            },
            stage_spy=True,
        )
        observed_processes.append(retrieve_proc)
        retrieve_data = retrieve_lines[-1]["data"]
        self.assertIn(
            denied_candidate_id,
            [candidate_resource_id(item) for item in retrieve_data["candidates"]],
        )
        self.assertNotIn(denied_candidate_body, json.dumps(retrieve_data))

        authorized_retrieval = [
            item
            for item in retrieve_data["candidates"]
            if candidate_resource_id(item) != denied_candidate_id
        ]
        intro = next(
            item for item in authorized_retrieval if candidate_resource_id(item) == adapter.FAKE_INTRO_ID
        )
        first_expand_proc, first_expand_lines = call_adapter(
            {
                "id": "x1",
                "method": "kag.expand",
                "params": authorized_params(frontier=[intro], limit=10),
            },
            stage_spy=True,
        )
        observed_processes.append(first_expand_proc)
        first_expand = first_expand_lines[-1]["data"]
        first_ids = [candidate_resource_id(item) for item in first_expand["candidates"]]
        self.assertIn(denied_frontier_id, first_ids)
        self.assertNotIn(adapter.FAKE_DENIED_CANARY_DETAIL_ID, json.dumps(first_expand))
        self.assertNotIn(denied_candidate_body, json.dumps(first_expand))

        authorized_frontier = [
            item
            for item in first_expand["candidates"]
            if candidate_resource_id(item) != denied_frontier_id
        ]
        second_expand_proc, second_expand_lines = call_adapter(
            {
                "id": "x2",
                "method": "kag.expand",
                "params": authorized_params(frontier=authorized_frontier, limit=10),
            },
            stage_spy=True,
        )
        observed_processes.append(second_expand_proc)
        second_expand = second_expand_lines[-1]["data"]
        second_serialized = json.dumps(second_expand)
        self.assertNotIn(denied_frontier_id, second_serialized)
        self.assertNotIn(adapter.FAKE_DENIED_NEXT_HOP_ID, second_serialized)
        self.assertNotIn(denied_frontier_body, second_serialized)
        self.assertEqual(
            second_expand["debug"]["stages"][0],
            {
                "stage": "expand.frontier_input",
                "resource_ids": [adapter.FAKE_LOCAL_FIRST_ID],
                "count": 1,
            },
        )

        authorized_evidence = [
            {
                "resource": fake_resource_handle(adapter.FAKE_INTRO_ID),
                "content": "knote is local-first.",
                "citation_handle": "cite_intro",
            },
            {
                "resource": fake_resource_handle(adapter.FAKE_LOCAL_FIRST_ID),
                "content": "Its runtime can authorize graph stages before generation.",
                "citation_handle": "cite_local_first",
            },
        ]
        generate_proc, generate_lines = call_adapter(
            {
                "id": "g",
                "method": "kag.generate",
                "params": authorized_params(
                    question="What is knote?", evidence=authorized_evidence
                ),
            },
            stage_spy=True,
        )
        observed_processes.append(generate_proc)
        generated = generate_lines[-1]["data"]
        generator_input_spy = generated["debug"]["stages"][0]
        self.assertEqual(generator_input_spy["stage"], "generate.evidence_input")
        self.assertEqual(generator_input_spy["count"], 2)
        for forbidden in (
            denied_candidate_id,
            denied_candidate_body,
            denied_frontier_id,
            denied_frontier_body,
            adapter.FAKE_DENIED_CANARY_DETAIL_ID,
            adapter.FAKE_DENIED_NEXT_HOP_ID,
        ):
            self.assertNotIn(forbidden, json.dumps(generated))
        for stage in generated["debug"]["stages"]:
            self.assertEqual(set(stage), {"stage", "resource_ids", "count"})
        for proc in observed_processes:
            observed = proc.stdout + proc.stderr
            self.assertNotIn(denied_candidate_body, observed)
            self.assertNotIn(denied_frontier_body, observed)

    def test_primitive_contract_rejects_malformed_input(self) -> None:
        valid_candidate = adapter.copy_fake_candidate(adapter.FAKE_INTRO_ID)
        valid_resource = fake_resource_handle(adapter.FAKE_INTRO_ID)
        auth = authorization_context()
        cases = [
            (
                {"id": "bad", "method": "kag.retrieve", "params": {"limit": 1}},
                "authorization must be an object",
            ),
            (
                {
                    "id": "bad",
                    "method": "kag.retrieve",
                    "params": {"authorization": auth, "limit": 1},
                },
                "query must be a non-empty string",
            ),
            (
                {
                    "id": "bad",
                    "method": "kag.retrieve",
                    "params": {"authorization": auth, "query": "q", "limit": 0},
                },
                "limit must be between 1 and 100",
            ),
            (
                {
                    "id": "bad",
                    "method": "kag.expand",
                    "params": {"authorization": auth, "frontier": valid_candidate},
                },
                "frontier must be a list",
            ),
            (
                {
                    "id": "bad",
                    "method": "kag.expand",
                    "params": {"authorization": auth, "frontier": []},
                },
                "frontier must be a list",
            ),
            (
                {
                    "id": "bad",
                    "method": "kag.expand",
                    "params": {
                        "authorization": auth,
                        "frontier": [{**valid_candidate, "content": "protected"}],
                    },
                },
                "unexpected content",
            ),
            (
                {
                    "id": "bad",
                    "method": "kag.expand",
                    "params": {
                        "authorization": auth,
                        "frontier": [{**valid_candidate, "score": float("nan")}],
                    },
                },
                "score must be finite",
            ),
            (
                {
                    "id": "bad",
                    "method": "kag.expand",
                    "params": {
                        "authorization": auth,
                        "frontier": [
                            {
                                **valid_candidate,
                                "resource": {**valid_resource, "resource_id": "res_not_opaque"},
                            }
                        ]
                    },
                },
                "must be an opaque res_ identifier",
            ),
            (
                {
                    "id": "bad",
                    "method": "kag.expand",
                    "params": {
                        "authorization": auth,
                        "frontier": [
                            {
                                **valid_candidate,
                                "resource": {
                                    **valid_resource,
                                    "versions": {
                                        **valid_resource["versions"],
                                        "projection": "projection_other",
                                    },
                                },
                            }
                        ]
                    },
                },
                "does not match the exact fake serving resource handle",
            ),
            (
                {
                    "id": "bad",
                    "method": "kag.generate",
                    "params": {"authorization": auth, "question": "q"},
                },
                "evidence must be a non-empty list",
            ),
            (
                {
                    "id": "bad",
                    "method": "kag.generate",
                    "params": {
                        "authorization": auth,
                        "question": "q",
                        "evidence": [
                            {"resource": valid_resource, "citation_handle": "cite_intro"}
                        ],
                    },
                },
                "missing content",
            ),
            (
                {
                    "id": "bad",
                    "method": "kag.generate",
                    "params": {
                        "authorization": auth,
                        "question": "q",
                        "evidence": [
                            {
                                "resource": {
                                    **valid_resource,
                                    "versions": {**valid_resource["versions"], "acl": "acl_other"},
                                },
                                "content": adapter.FAKE_CONTENT_BY_ID[adapter.FAKE_INTRO_ID],
                                "citation_handle": "cite_intro",
                            }
                        ],
                    },
                },
                "does not match the exact fake serving resource handle",
            ),
            (
                {
                    "id": "bad",
                    "method": "kag.generate",
                    "params": {
                        "authorization": auth,
                        "question": "q",
                        "evidence": [
                            {
                                "resource": valid_resource,
                                "content": "body from a different resource",
                                "citation_handle": "cite_intro",
                            }
                        ],
                    },
                },
                "does not match resource.content_digest",
            ),
            (
                {"id": "bad", "method": "kag.retrieve", "params": []},
                "params must be an object",
            ),
        ]
        for request, expected_error in cases:
            with self.subTest(expected_error=expected_error):
                _, lines = call_adapter(request)
                response = lines[-1]
                self.assertEqual(response["type"], "error")
                self.assertEqual(response["code"], "invalid_request")
                self.assertIn(expected_error, response["error"])

    def test_non_object_request_is_a_typed_error(self) -> None:
        _, lines = call_adapter([])

        self.assertEqual(
            lines[-1],
            {"id": "", "type": "error", "error": "request must be a JSON object", "code": "invalid_request"},
        )

    def test_real_primitives_fail_before_any_kag_setup(self) -> None:
        for method in sorted(adapter.PRIMITIVE_METHODS):
            with self.subTest(method=method):
                stdout = StringIO()
                with (
                    patch.object(adapter, "runtime_dir") as runtime_dir_mock,
                    patch.object(adapter, "select_config") as select_config_mock,
                    patch.object(adapter, "check_real_health") as health_mock,
                    patch.object(adapter, "run_capturing_stdout") as capture_mock,
                    redirect_stdout(stdout),
                ):
                    adapter.real_response({"id": "real", "method": method, "params": "malformed but unused"})

                response = json.loads(stdout.getvalue())
                self.assertEqual(response["id"], "real")
                self.assertEqual(response["type"], "error")
                self.assertEqual(response["code"], "unsupported_primitive")
                self.assertIn(method, response["error"])
                runtime_dir_mock.assert_not_called()
                select_config_mock.assert_not_called()
                health_mock.assert_not_called()
                capture_mock.assert_not_called()

    def test_error_json_remains_compatible_when_code_is_absent(self) -> None:
        stdout = StringIO()
        with redirect_stdout(stdout):
            adapter.error("legacy", "legacy error")
            adapter.error("typed", "typed error", "unsupported_primitive")

        lines = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual(lines[0], {"id": "legacy", "type": "error", "error": "legacy error"})
        self.assertEqual(
            lines[1],
            {"id": "typed", "type": "error", "error": "typed error", "code": "unsupported_primitive"},
        )

    def test_legacy_fake_query_explain_and_cancel_are_unchanged(self) -> None:
        expected = {
            "answer": "Fake KAG answer for: legacy question",
            "evidence": ["tests/fixtures/basic-kb/sources/intro.md"],
            "uncertainty": "fake adapter mode",
        }
        for method in ("kag.query", "kag.explain"):
            with self.subTest(method=method):
                _, lines = call_adapter(
                    {"id": "legacy", "method": method, "params": {"query": "legacy question"}}
                )
                self.assertEqual(lines[-1]["data"], expected)
        for fake in (True, False):
            with self.subTest(fake=fake):
                _, lines = call_adapter({"id": "cancel", "method": "kag.cancel"}, fake=fake)
                self.assertEqual(lines[-1]["data"], {"status": "cancelled"})

    def test_fake_primitive_process_can_be_stopped_by_timeout(self) -> None:
        env = os.environ.copy()
        env["KNOTE_KAG_FAKE"] = "1"
        env[adapter.TEST_DELAY_MS_ENV] = "500"
        request = {
            "id": "slow",
            "method": "kag.retrieve",
            "params": authorized_params(query="q"),
        }

        with self.assertRaises(subprocess.TimeoutExpired):
            subprocess.run(
                [sys.executable, str(ADAPTER_PATH)],
                input=json.dumps(request) + "\n",
                text=True,
                capture_output=True,
                cwd=ROOT,
                env=env,
                timeout=0.05,
                check=True,
            )

    def test_prepare_corpus_is_sorted_and_stable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "sources" / "nested").mkdir(parents=True)
            (workspace / "sources" / "z.txt").write_text("Zed", encoding="utf-8")
            (workspace / "sources" / "a.md").write_text("# Alpha\n\nBody", encoding="utf-8")
            (workspace / "sources" / "nested" / "b.md").write_text("# Beta", encoding="utf-8")

            corpus_path, records = adapter.prepare_corpus(workspace, workspace / ".knote" / "kag-runtime")

            self.assertEqual([r["id"] for r in records], ["sources/a.md", "sources/nested/b.md", "sources/z.txt"])
            self.assertEqual(records[0]["name"], "Alpha")
            on_disk = json.loads(corpus_path.read_text(encoding="utf-8"))
            self.assertEqual(on_disk, records)

    def test_prepare_corpus_keeps_runtime_cache_out_of_git_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            subprocess.run(["git", "init"], cwd=workspace, text=True, capture_output=True, check=True)
            (workspace / "sources").mkdir()
            (workspace / "sources" / "intro.md").write_text("# Intro", encoding="utf-8")

            adapter.prepare_corpus(workspace, workspace / ".knote" / "kag-runtime")

            status = subprocess.run(["git", "status", "--short"], cwd=workspace, text=True, capture_output=True, check=True)
            self.assertEqual(status.stdout, "?? sources/\n")
            exclude = workspace / ".git" / "info" / "exclude"
            self.assertIn("/.knote/kag-runtime/", exclude.read_text(encoding="utf-8"))

    def test_prepare_corpus_excludes_runtime_cache_in_parent_git_repo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            workspace = repo / "tests" / "fixtures" / "basic-kb"
            subprocess.run(["git", "init"], cwd=repo, text=True, capture_output=True, check=True)
            (workspace / "sources").mkdir(parents=True)
            (workspace / "sources" / "intro.md").write_text("# Intro", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=repo, text=True, capture_output=True, check=True)
            subprocess.run(
                ["git", "-c", "user.name=test", "-c", "user.email=test@example.com", "commit", "-m", "init"],
                cwd=repo,
                text=True,
                capture_output=True,
                check=True,
            )

            adapter.prepare_corpus(workspace, workspace / ".knote" / "kag-runtime")

            status = subprocess.run(["git", "status", "--short"], cwd=repo, text=True, capture_output=True, check=True)
            self.assertEqual(status.stdout, "")
            exclude = repo / ".git" / "info" / "exclude"
            self.assertIn("/tests/fixtures/basic-kb/.knote/kag-runtime/", exclude.read_text(encoding="utf-8"))

    def test_generated_config_uses_workspace_runtime_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            params = {
                "workspace": str(workspace),
                "host": "http://127.0.0.1:8887",
                "project_id": "7",
                "namespace": "KnoteTest",
                "language": "zh",
            }
            config_path = adapter.select_config(params, workspace / ".knote" / "kag-runtime")

            text = config_path.read_text(encoding="utf-8")
            self.assertNotIn("{{", text)
            self.assertIn('base_url: "http://localhost:11434/v1"', text)
            self.assertIn('model: "qwen2.5-7b-instruct"', text)
            self.assertIn('type: "openai"', text)
            self.assertIn("vector_dimensions: 1024", text)
            self.assertIn("host_addr: http://127.0.0.1:8887", text)
            self.assertIn('id: "7"', text)
            self.assertIn("namespace: KnoteTest", text)
            self.assertIn('checkpoint_path: "', text)
            self.assertIn("/.knote/kag-runtime/ckpt", text)
            self.assertIn("scanner:\n    type: json_scanner", text)
            self.assertIn("kag_solver_pipeline:\n  type: kag_static_pipeline", text)
            self.assertIn("planner:\n    type: lf_kag_static_planner", text)
            self.assertIn("executors:\n    - *kag_hybrid_executor_conf", text)
            self.assertIn("type: llm_index_generator", text)

    def test_generated_config_renders_kag_model_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            params = {"workspace": str(workspace), "host": "http://127.0.0.1:8887"}
            env = {
                "KNOTE_OPENIE_LLM_TYPE": "openai",
                "KNOTE_OPENIE_LLM_BASE_URL": "http://127.0.0.1:8317/v1",
                "KNOTE_OPENIE_LLM_API_KEY": "local:key",
                "KNOTE_OPENIE_LLM_MODEL": "gpt-5.3-codex-spark",
                "KNOTE_CHAT_LLM_TYPE": "openai",
                "KNOTE_CHAT_LLM_BASE_URL": "http://127.0.0.1:8317/v1",
                "KNOTE_CHAT_LLM_API_KEY": "local:key",
                "KNOTE_CHAT_LLM_MODEL": "gpt-5.3-codex-spark",
                "KNOTE_VECTOR_TYPE": "mock",
                "KNOTE_VECTOR_DIMENSIONS": "256",
            }

            with patch.dict(os.environ, env, clear=False):
                config_path = adapter.select_config(params, workspace / ".knote" / "kag-runtime")

            text = config_path.read_text(encoding="utf-8")
            self.assertNotIn("{{", text)
            self.assertIn('base_url: "http://127.0.0.1:8317/v1"', text)
            self.assertNotIn("local:key", text)
            self.assertIn("api_key: !ENV KNOTE_OPENIE_LLM_API_KEY", text)
            self.assertIn("api_key: !ENV KNOTE_CHAT_LLM_API_KEY", text)
            self.assertIn('model: "gpt-5.3-codex-spark"', text)
            self.assertIn('type: "mock"', text)
            self.assertIn("vector_dimensions: 256", text)

    def test_generated_runtime_config_is_refreshed_on_build_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            runtime_dir = workspace / ".knote" / "kag-runtime"
            params = {"workspace": str(workspace)}

            with patch.dict(os.environ, {"KNOTE_OPENIE_LLM_MODEL": "first"}, clear=False):
                config_path = adapter.select_config(params, runtime_dir)
            self.assertIn('model: "first"', config_path.read_text(encoding="utf-8"))

            with patch.dict(os.environ, {"KNOTE_OPENIE_LLM_MODEL": "second"}, clear=False):
                config_path = adapter.select_config(params, runtime_dir)
            text = config_path.read_text(encoding="utf-8")
            self.assertIn('model: "second"', text)
            self.assertNotIn('model: "first"', text)

    def test_generated_config_keeps_env_api_keys_dynamic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            params = {"workspace": str(workspace)}
            env = {
                "KNOTE_OPENIE_LLM_API_KEY": "openie-secret",
                "KNOTE_CHAT_LLM_API_KEY": "chat-secret",
                "KNOTE_VECTOR_API_KEY": "vector-secret",
            }

            with patch.dict(os.environ, env, clear=False):
                config_path = adapter.select_config(params, workspace / ".knote" / "kag-runtime")

            text = config_path.read_text(encoding="utf-8")
            self.assertIn("api_key: !ENV KNOTE_OPENIE_LLM_API_KEY", text)
            self.assertIn("api_key: !ENV KNOTE_CHAT_LLM_API_KEY", text)
            self.assertIn("api_key: !ENV KNOTE_VECTOR_API_KEY", text)
            self.assertNotIn("openie-secret", text)
            self.assertNotIn("chat-secret", text)
            self.assertNotIn("vector-secret", text)

    def test_local_no_proxy_preserves_existing_entries(self) -> None:
        with patch.dict(os.environ, {"NO_PROXY": "example.com"}, clear=True):
            adapter.ensure_local_no_proxy({"host": "http://127.0.0.1:8887"})

            entries = os.environ["NO_PROXY"].split(",")
            self.assertEqual(entries[0], "example.com")
            self.assertIn("localhost", entries)
            self.assertIn("127.0.0.1", entries)
            self.assertEqual(os.environ["no_proxy"], os.environ["NO_PROXY"])

    def test_local_no_proxy_merges_lowercase_env(self) -> None:
        with patch.dict(os.environ, {"no_proxy": "example.org"}, clear=True):
            adapter.ensure_local_no_proxy({"host": "http://localhost:8887"})

            entries = os.environ["NO_PROXY"].split(",")
            self.assertEqual(entries[0], "example.org")
            self.assertIn("localhost", entries)
            self.assertEqual(os.environ["no_proxy"], os.environ["NO_PROXY"])

    def test_local_no_proxy_collects_config_and_private_hosts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "kag_config.yaml"
            config_path.write_text(
                "\n".join(
                    [
                        "project:",
                        "  host_addr: http://192.168.31.59:8887",
                        "openie_llm:",
                        "  base_url: http://127.0.0.1:8317/v1",
                        "chat_llm:",
                        "  base_url: https://api.openai.com/v1",
                    ]
                ),
                encoding="utf-8",
            )

            with patch.dict(os.environ, {}, clear=True):
                adapter.ensure_local_no_proxy({"host": "http://127.0.0.1:8887"}, config_path)

                entries = os.environ["NO_PROXY"].split(",")
                self.assertIn("127.0.0.1", entries)
                self.assertIn("192.168.31.59", entries)
                self.assertNotIn("api.openai.com", entries)

    def test_local_no_proxy_resolves_env_config_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "kag_config.yaml"
            config_path.write_text(
                "\n".join(
                    [
                        "openie_llm:",
                        "  base_url: !ENV KNOTE_OPENIE_LLM_BASE_URL",
                        "chat_llm:",
                        "  base_url: !ENV KNOTE_CHAT_LLM_BASE_URL",
                    ]
                ),
                encoding="utf-8",
            )
            env = {
                "KNOTE_OPENIE_LLM_BASE_URL": "http://127.0.0.1:8317/v1",
                "KNOTE_CHAT_LLM_BASE_URL": "https://api.openai.com/v1",
            }

            with patch.dict(os.environ, env, clear=True):
                adapter.ensure_local_no_proxy({}, config_path)

                entries = os.environ["NO_PROXY"].split(",")
                self.assertIn("127.0.0.1", entries)
                self.assertNotIn("api.openai.com", entries)

    def test_generated_config_rejects_invalid_vector_dimensions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            params = {"workspace": str(workspace)}

            with patch.dict(os.environ, {"KNOTE_VECTOR_DIMENSIONS": "wide"}, clear=False):
                with self.assertRaisesRegex(RuntimeError, "KNOTE_VECTOR_DIMENSIONS must be an integer"):
                    adapter.select_config(
                        params,
                        workspace / ".knote" / "kag-runtime",
                    )

    def test_explicit_config_path_must_exist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            params = {"workspace": str(workspace), "config_path": "missing.yaml"}

            with self.assertRaisesRegex(FileNotFoundError, "explicit KAG config not found"):
                adapter.select_config(params, workspace / ".knote" / "kag-runtime")

    def test_projection_namespace_materializes_isolated_explicit_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            base = workspace / ".knote" / "kag_config.yaml"
            base.parent.mkdir(parents=True)
            base.write_text(
                "project:\n  host_addr: http://127.0.0.1:8887\n  namespace: shared\n  checkpoint_path: shared/ckpt\n",
                encoding="utf-8",
            )
            out_dir = workspace / ".knote" / "kag-runtime" / "projections" / "projection-one"
            selected = adapter.select_config(
                {
                    "workspace": str(workspace),
                    "config_path": str(base),
                    "namespace": "projection-one",
                },
                out_dir,
            )
            text = selected.read_text(encoding="utf-8")
            self.assertEqual(selected, (out_dir / "kag_config.yaml").resolve())
            self.assertIn('namespace: "projection-one"', text)
            self.assertIn(f'checkpoint_path: "{out_dir / "ckpt"}"', text)
            self.assertIn("namespace: shared", base.read_text(encoding="utf-8"))

    def test_projection_build_scopes_checkpoint_to_idempotency_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            base = workspace / ".knote" / "kag_config.yaml"
            base.parent.mkdir(parents=True)
            base.write_text(
                "project:\n  namespace: shared\n  checkpoint_path: shared/ckpt\n",
                encoding="utf-8",
            )
            out_dir = workspace / ".knote" / "kag-runtime" / "projections" / "projection-one"
            key = "sync-projection-one"
            params = {
                "workspace": str(workspace),
                "config_path": str(base),
                "namespace": "projection-one",
                "idempotency_key": key,
            }

            selected = adapter.select_config(params, out_dir, generate=True)
            digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
            expected_checkpoint = out_dir / "ckpt" / "runs" / digest
            self.assertIn(f'checkpoint_path: "{expected_checkpoint}"', selected.read_text(encoding="utf-8"))

            before = selected.read_bytes()
            self.assertEqual(adapter.select_config(params, out_dir, generate=False).read_bytes(), before)

    def test_projection_config_accepts_inline_comment_and_anchor_project_mappings(self) -> None:
        cases = {
            "inline": (
                "project: {host_addr: http://127.0.0.1:8887, namespace: shared, checkpoint_path: shared/ckpt}\n"
                "openie_llm:\n  api_key: !ENV KNOTE_OPENIE_LLM_API_KEY\n"
                "kag_builder_pipeline:\n  type: custom_builder\n"
            ),
            "comment": (
                "project: # shared project settings\n"
                "  host_addr: http://127.0.0.1:8887\n"
                "  namespace: shared\n"
                "kag_builder_pipeline:\n  type: custom_builder\n"
            ),
            "anchor": (
                "project: &shared_project\n"
                "  host_addr: http://127.0.0.1:8887\n"
                "  namespace: shared\n"
                "project_copy: *shared_project\n"
                "kag_builder_pipeline:\n  type: custom_builder\n"
            ),
        }
        for name, config in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                workspace = Path(tmp)
                base = workspace / ".knote" / "kag_config.yaml"
                base.parent.mkdir(parents=True)
                base.write_text(config, encoding="utf-8")
                out_dir = workspace / ".knote" / "kag-runtime" / "projections" / "projection-one"
                key = f"sync-{name}"

                selected = adapter.select_config(
                    {
                        "workspace": str(workspace),
                        "config_path": str(base),
                        "namespace": "projection-one",
                        "idempotency_key": key,
                    },
                    out_dir,
                )

                digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
                text = selected.read_text(encoding="utf-8")
                self.assertIn('namespace: "projection-one"', text)
                self.assertIn(f'checkpoint_path: "{out_dir / "ckpt" / "runs" / digest}"', text)
                if name == "inline":
                    self.assertIn("api_key: !ENV KNOTE_OPENIE_LLM_API_KEY", text)
                self.assertIn("kag_builder_pipeline:\n  type: custom_builder", text)
                self.assertEqual(base.read_text(encoding="utf-8"), config)
                if name == "inline":
                    self.assertIn("project: {host_addr:", text)
                    self.assertNotIn("namespace: shared", text)
                    self.assertNotIn("checkpoint_path: shared/ckpt", text)
                elif name == "comment":
                    self.assertIn("project: # shared project settings", text)
                else:
                    self.assertIn("project: &shared_project", text)
                    self.assertIn("project_copy: *shared_project", text)

    def test_projection_config_rejects_malformed_project_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            base = workspace / "kag_config.yaml"
            base.write_text("project: {host_addr: http://127.0.0.1:8887\n", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "invalid KAG config YAML"):
                adapter.projection_config(
                    base,
                    workspace / ".knote" / "kag-runtime" / "projections" / "projection-one",
                    {"workspace": str(workspace), "namespace": "projection-one"},
                )

    def test_projection_config_rejects_non_mapping_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            base = workspace / "kag_config.yaml"
            base.write_text("project: not-a-mapping\n", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "project section must be a mapping"):
                adapter.projection_config(
                    base,
                    workspace / ".knote" / "kag-runtime" / "projections" / "projection-one",
                    {"workspace": str(workspace), "namespace": "projection-one"},
                )

    def test_projection_build_uses_source_config_directory_for_imports_and_resources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            config_dir = workspace / "kag_project"
            config_dir.mkdir()
            config_dir = config_dir.resolve()
            base = config_dir / "kag_config.yaml"
            base.write_text(
                "project:\n  namespace: shared\n"
                "kag_builder_pipeline:\n  type: custom_builder\n",
                encoding="utf-8",
            )
            (config_dir / "prompt.txt").write_text("source-relative prompt", encoding="utf-8")
            (workspace / "sources").mkdir()
            (workspace / "sources" / "intro.md").write_text("# Intro", encoding="utf-8")
            out_dir = workspace / ".knote" / "kag-runtime" / "projections" / "projection-one"
            params = {
                "workspace": str(workspace),
                "runtime_dir": str(out_dir),
                "config_path": str(base),
                "namespace": "projection-one",
                "idempotency_key": "sync-projection-one",
            }
            seen: dict[str, object] = {}

            class FakeBuilderChainRunner:
                @classmethod
                def from_config(cls, pipeline: object) -> "FakeBuilderChainRunner":
                    seen["builder_cwd"] = Path.cwd()
                    seen["prompt"] = Path("prompt.txt").read_text(encoding="utf-8")
                    return cls()

                def invoke(self, corpus_path: str) -> None:
                    seen["invoke_cwd"] = Path.cwd()
                    seen["invoke_calls"] = int(seen.get("invoke_calls", 0)) + 1
                    adapter.build_checkpoint_path(out_dir, params).mkdir(parents=True, exist_ok=True)
                    print("Done process 1 records, with 1 successfully processed and 0 failures encountered")

            def fake_import_modules(path: str) -> None:
                seen["import_path"] = Path(path)
                seen["import_cwd"] = Path.cwd()

            def fake_init(config_path: Path) -> None:
                seen["config_path"] = config_path
                seen["init_cwd"] = Path.cwd()

            kag_config = types.SimpleNamespace(all_config={"kag_builder_pipeline": {"type": "custom_builder"}})
            runner_module = types.ModuleType("kag.builder.runner")
            runner_module.BuilderChainRunner = FakeBuilderChainRunner
            conf_module = types.ModuleType("kag.common.conf")
            conf_module.KAG_CONFIG = kag_config
            registry_module = types.ModuleType("kag.common.registry")
            registry_module.import_modules_from_path = fake_import_modules
            modules = {
                "kag": types.ModuleType("kag"),
                "kag.builder": types.ModuleType("kag.builder"),
                "kag.builder.runner": runner_module,
                "kag.common": types.ModuleType("kag.common"),
                "kag.common.conf": conf_module,
                "kag.common.registry": registry_module,
            }
            original_cwd = Path.cwd()

            with (
                patch.dict(sys.modules, modules),
                patch.object(adapter, "init_kag_config", fake_init),
                patch.object(adapter, "ensure_local_no_proxy"),
            ):
                data = adapter.run_kag_build({"id": "build", "method": "kag.build", "params": params})
                (workspace / "sources" / "intro.md").unlink()
                replay = adapter.run_kag_build({"id": "build-replay", "method": "kag.build", "params": params})
                (workspace / "sources" / "intro.md").write_text("# Intro", encoding="utf-8")
                adapter.build_checkpoint_path(out_dir, params).rmdir()
                rebuilt = adapter.run_kag_build({"id": "build-repair", "method": "kag.build", "params": params})

            projected = (out_dir / "kag_config.yaml").resolve()
            self.assertEqual(Path.cwd(), original_cwd)
            self.assertEqual(seen["config_path"], projected)
            self.assertEqual(seen["import_path"], config_dir)
            self.assertEqual(seen["init_cwd"], config_dir)
            self.assertEqual(seen["import_cwd"], config_dir)
            self.assertEqual(seen["builder_cwd"], config_dir)
            self.assertEqual(seen["invoke_cwd"], config_dir)
            self.assertEqual(seen["invoke_calls"], 2)
            self.assertEqual(seen["prompt"], "source-relative prompt")
            self.assertEqual(data["config_path"], str(projected))
            self.assertEqual(data["idempotency_key"], "sync-projection-one")
            self.assertEqual(replay, data)
            self.assertEqual(rebuilt, data)
            self.assertTrue(adapter.build_receipt_path(out_dir.resolve(), "sync-projection-one").exists())

    def test_projection_query_uses_source_config_directory_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            config_dir = workspace / "kag_project"
            config_dir.mkdir()
            config_dir = config_dir.resolve()
            base = config_dir / "kag_config.yaml"
            base.write_text(
                "project:\n  namespace: shared\n"
                "kag_solver_pipeline:\n  type: custom_solver\n",
                encoding="utf-8",
            )
            (config_dir / "prompt.txt").write_text("source-relative prompt", encoding="utf-8")
            out_dir = workspace / ".knote" / "kag-runtime" / "projections" / "projection-one"
            params = {
                "workspace": str(workspace),
                "runtime_dir": str(out_dir),
                "config_path": str(base),
                "namespace": "projection-one",
                "query": "hello",
            }
            projected = adapter.select_config(params, out_dir, generate=True)
            before = projected.read_bytes()
            seen: dict[str, object] = {}

            class FakeSolver:
                def run(self, query: str) -> str:
                    seen["run_cwd"] = Path.cwd()
                    return "answer: " + query

            class FakeSolverPipelineABC:
                @classmethod
                def from_config(cls, pipeline: object) -> FakeSolver:
                    seen["solver_cwd"] = Path.cwd()
                    seen["prompt"] = Path("prompt.txt").read_text(encoding="utf-8")
                    return FakeSolver()

            def fake_import_modules(path: str) -> None:
                seen["import_path"] = Path(path)

            def fake_init(config_path: Path) -> None:
                seen["config_path"] = config_path
                seen["init_cwd"] = Path.cwd()

            kag_config = types.SimpleNamespace(all_config={"kag_solver_pipeline": {"type": "custom_solver"}})
            conf_module = types.ModuleType("kag.common.conf")
            conf_module.KAG_CONFIG = kag_config
            registry_module = types.ModuleType("kag.common.registry")
            registry_module.import_modules_from_path = fake_import_modules
            interface_module = types.ModuleType("kag.interface")
            interface_module.SolverPipelineABC = FakeSolverPipelineABC
            modules = {
                "kag": types.ModuleType("kag"),
                "kag.common": types.ModuleType("kag.common"),
                "kag.common.conf": conf_module,
                "kag.common.registry": registry_module,
                "kag.interface": interface_module,
            }

            with (
                patch.dict(sys.modules, modules),
                patch.object(adapter, "init_kag_config", fake_init),
                patch.object(adapter, "ensure_local_no_proxy"),
            ):
                data = adapter.run_kag_query({"id": "query", "method": "kag.query", "params": params})

            self.assertEqual(seen["config_path"], projected)
            self.assertEqual(seen["import_path"], config_dir)
            self.assertEqual(seen["init_cwd"], config_dir)
            self.assertEqual(seen["solver_cwd"], config_dir)
            self.assertEqual(seen["run_cwd"], config_dir)
            self.assertEqual(seen["prompt"], "source-relative prompt")
            self.assertEqual(data["answer"], "answer: hello")
            self.assertEqual(projected.read_bytes(), before)

    def test_projection_query_and_explain_regenerate_checkout_runtime_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            base, runtime, projection_id = initialize_checkout_projection(workspace)
            original = base.read_bytes()
            params = {
                "workspace": str(workspace),
                "runtime_dir": str(runtime),
                "namespace": "projection-one",
                "projection_isolated": True,
                "query": "hello",
            }

            class FakeSolver:
                def run(self, query: str) -> dict[str, str]:
                    return {"answer": "answer: " + query, "trace": "checkout trace"}

            class FakeSolverPipelineABC:
                @classmethod
                def from_config(cls, pipeline: object) -> FakeSolver:
                    return FakeSolver()

            kag_config = types.SimpleNamespace(
                all_config={"kag_solver_pipeline": {"type": "custom_solver"}}
            )
            conf_module = types.ModuleType("kag.common.conf")
            conf_module.KAG_CONFIG = kag_config
            registry_module = types.ModuleType("kag.common.registry")
            registry_module.import_modules_from_path = lambda path: None
            interface_module = types.ModuleType("kag.interface")
            interface_module.SolverPipelineABC = FakeSolverPipelineABC
            modules = {
                "kag": types.ModuleType("kag"),
                "kag.common": types.ModuleType("kag.common"),
                "kag.common.conf": conf_module,
                "kag.common.registry": registry_module,
                "kag.interface": interface_module,
            }

            for method in ("kag.query", "kag.explain"):
                with self.subTest(method=method):
                    shutil.rmtree(runtime, ignore_errors=True)
                    stdout = StringIO()
                    with (
                        patch.dict(sys.modules, modules),
                        patch.object(adapter, "init_kag_config"),
                        patch.object(adapter, "check_real_health", return_value=({"status": "ok"}, None)) as health,
                        redirect_stdout(stdout),
                    ):
                        adapter.real_response({"id": method, "method": method, "params": params})

                    response = json.loads(stdout.getvalue().splitlines()[-1])
                    self.assertEqual(response["type"], "result")
                    self.assertEqual(response["data"]["answer"], "answer: hello")
                    if method == "kag.explain":
                        self.assertEqual(response["data"]["explanation"], "checkout trace")
                    health.assert_called_once()
                    projected = runtime / "kag_config.yaml"
                    text = projected.read_text(encoding="utf-8")
                    key = "kag-build-" + projection_id
                    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
                    self.assertIn('namespace: "projection-one"', text)
                    self.assertIn(
                        f'checkpoint_path: "{runtime / "ckpt" / "runs" / digest}"',
                        text,
                    )
                    self.assertEqual(response["data"]["config_path"], str(projected.resolve()))
                    self.assertEqual(base.read_bytes(), original)

    def test_projection_checkout_regeneration_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            base, runtime, _ = initialize_checkout_projection(workspace)
            params = {
                "workspace": str(workspace),
                "runtime_dir": str(runtime),
                "namespace": "projection-other",
                "projection_isolated": True,
            }

            with self.assertRaisesRegex(FileNotFoundError, "projection KAG config not found"):
                adapter.select_config(params, runtime, generate=False)

            params["namespace"] = "projection-one"
            base.write_text(base.read_text(encoding="utf-8") + "# dirty\n", encoding="utf-8")
            with self.assertRaisesRegex(FileNotFoundError, "projection KAG config not found"):
                adapter.select_config(params, runtime, generate=False)
            self.assertFalse(runtime.exists())

    def test_projection_checkout_regeneration_does_not_bypass_health(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            _, runtime, _ = initialize_checkout_projection(workspace)
            params = {
                "workspace": str(workspace),
                "runtime_dir": str(runtime),
                "namespace": "projection-one",
                "projection_isolated": True,
                "query": "hello",
            }
            stdout = StringIO()

            with (
                patch.object(adapter, "check_real_health", return_value=(None, "health denied")) as health,
                patch.object(adapter, "run_kag_query") as query,
                redirect_stdout(stdout),
            ):
                adapter.real_response({"id": "query", "method": "kag.query", "params": params})

            response = json.loads(stdout.getvalue())
            self.assertEqual(response["type"], "error")
            self.assertEqual(response["error"], "health denied")
            health.assert_called_once()
            query.assert_not_called()
            self.assertTrue((runtime / "kag_config.yaml").is_file())

    def test_projection_query_requires_prebuilt_config_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            base = workspace / ".knote" / "kag_config.yaml"
            base.parent.mkdir(parents=True)
            original = "project:\n  host_addr: http://127.0.0.1:8887\n  namespace: shared\n"
            base.write_text(original, encoding="utf-8")
            out_dir = workspace / ".knote" / "kag-runtime" / "projections" / "projection-one"
            params = {
                "workspace": str(workspace),
                "config_path": str(base),
                "namespace": "projection-one",
            }

            with self.assertRaisesRegex(FileNotFoundError, "projection KAG config not found"):
                adapter.select_config(params, out_dir, generate=False)

            self.assertFalse(out_dir.exists())
            self.assertEqual(base.read_text(encoding="utf-8"), original)

            built = adapter.select_config(params, out_dir, generate=True)
            before = built.read_bytes()
            selected = adapter.select_config(params, out_dir, generate=False)
            self.assertEqual(selected, built)
            self.assertEqual(selected.read_bytes(), before)

    def test_legacy_namespace_queries_use_base_config_without_projection_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            base = workspace / ".knote" / "kag_config.yaml"
            base.parent.mkdir(parents=True)
            base.write_text("project:\n  namespace: legacy\n", encoding="utf-8")
            runtime = workspace / ".knote" / "kag-runtime"
            params = {
                "workspace": str(workspace),
                "config_path": str(base),
                "namespace": "legacy",
                "runtime_dir": str(runtime),
            }

            for method in ("kag.query", "kag.explain"):
                with self.subTest(method=method):
                    selected = adapter.select_config(params, runtime, generate=False)
                    self.assertEqual(selected, base.resolve())

            self.assertFalse((runtime / "kag_config.yaml").exists())

    def test_projection_runtime_marker_still_requires_prebuilt_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            base = workspace / ".knote" / "kag_config.yaml"
            base.parent.mkdir(parents=True)
            base.write_text("project:\n  namespace: shared\n", encoding="utf-8")
            runtime = workspace / ".knote" / "kag-runtime" / "projections" / "projection-one"
            params = {
                "workspace": str(workspace),
                "config_path": str(base),
                "namespace": "projection-one",
                "runtime_dir": str(runtime),
            }

            with self.assertRaisesRegex(FileNotFoundError, "projection KAG config not found"):
                adapter.select_config(params, runtime, generate=False)

            self.assertFalse(runtime.exists())

    def test_select_config_excludes_generated_config_from_git_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            subprocess.run(["git", "init"], cwd=workspace, text=True, capture_output=True, check=True)

            adapter.select_config({"workspace": str(workspace)}, workspace / ".knote" / "kag-runtime")

            status = subprocess.run(["git", "status", "--short"], cwd=workspace, text=True, capture_output=True, check=True)
            self.assertEqual(status.stdout, "")
            exclude = workspace / ".git" / "info" / "exclude"
            self.assertIn("/.knote/kag-runtime/", exclude.read_text(encoding="utf-8"))

    def test_select_config_can_require_existing_config_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            subprocess.run(["git", "init"], cwd=workspace, text=True, capture_output=True, check=True)

            with self.assertRaisesRegex(FileNotFoundError, "KAG config not found"):
                adapter.select_config({"workspace": str(workspace)}, workspace / ".knote" / "kag-runtime", generate=False)

            status = subprocess.run(["git", "status", "--short"], cwd=workspace, text=True, capture_output=True, check=True)
            self.assertEqual(status.stdout, "")
            self.assertFalse((workspace / ".knote").exists())

    def test_select_config_reuses_runtime_generated_config_for_queries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            runtime_dir = workspace / ".knote" / "kag-runtime"
            runtime_dir.mkdir(parents=True)
            generated = runtime_dir / "kag_config.yaml"
            generated.write_text("project:\n  host_addr: http://127.0.0.1:8887\n", encoding="utf-8")

            selected = adapter.select_config({"workspace": str(workspace)}, runtime_dir, generate=False)

            self.assertEqual(selected, generated.resolve())

    def test_real_query_without_config_is_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            subprocess.run(["git", "init"], cwd=workspace, text=True, capture_output=True, check=True)
            stdout = StringIO()
            req = {"id": "q1", "method": "kag.query", "params": {"workspace": str(workspace), "query": "hello"}}

            with redirect_stdout(stdout):
                adapter.real_response(req)

            line = json.loads(stdout.getvalue().strip())
            self.assertEqual(line["type"], "error")
            self.assertIn("KAG config not found", line["error"])
            status = subprocess.run(["git", "status", "--short"], cwd=workspace, text=True, capture_output=True, check=True)
            self.assertEqual(status.stdout, "")
            self.assertFalse((workspace / ".knote").exists())

    def test_real_build_replays_receipt_before_config_and_health(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            runtime = workspace / ".knote" / "kag-runtime" / "projections" / "projection-one"
            params = {
                "workspace": str(workspace),
                "runtime_dir": str(runtime),
                "namespace": "projection-one",
                "idempotency_key": "sync-projection-one",
            }
            config_path = runtime / "kag_config.yaml"
            config_path.parent.mkdir(parents=True)
            config_path.write_text("project:\n  namespace: projection-one\n", encoding="utf-8")
            adapter.build_checkpoint_path(runtime, params).mkdir(parents=True)
            receipt = {
                "status": "ok",
                "mode": "real",
                "documents": 1,
                "config_path": str(config_path.resolve()),
            }
            adapter.store_build_receipt(runtime, params["idempotency_key"], receipt)
            stdout = StringIO()

            with (
                patch.object(adapter, "select_config") as select_config_mock,
                patch.object(adapter, "check_real_health") as health_mock,
                redirect_stdout(stdout),
            ):
                adapter.real_response({"id": "build-replay", "method": "kag.build", "params": params})

            response = json.loads(stdout.getvalue())
            self.assertEqual(response["type"], "result")
            self.assertEqual(response["data"], receipt)
            select_config_mock.assert_not_called()
            health_mock.assert_not_called()

    def test_real_build_repairs_incomplete_projection_runtime_instead_of_replaying(self) -> None:
        for missing in ("config", "checkpoint"):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as tmp:
                workspace = Path(tmp)
                base = workspace / ".knote" / "kag_config.yaml"
                base.parent.mkdir(parents=True)
                base.write_text("project:\n  namespace: shared\n", encoding="utf-8")
                runtime = workspace / ".knote" / "kag-runtime" / "projections" / "projection-one"
                params = {
                    "workspace": str(workspace),
                    "runtime_dir": str(runtime),
                    "config_path": str(base),
                    "namespace": "projection-one",
                    "idempotency_key": "sync-projection-one",
                }
                projected = adapter.select_config(params, runtime)
                adapter.build_checkpoint_path(runtime, params).mkdir(parents=True)
                receipt = {
                    "status": "ok",
                    "mode": "real",
                    "documents": 1,
                    "config_path": str(projected),
                }
                adapter.store_build_receipt(runtime, params["idempotency_key"], receipt)
                if missing == "config":
                    projected.unlink()
                else:
                    adapter.build_checkpoint_path(runtime, params).rmdir()

                stdout = StringIO()
                rebuilt = {"status": "ok", "mode": "real", "documents": 1, "repaired": True}
                with (
                    patch.object(adapter, "check_real_health", return_value=({"status": "ok"}, None)),
                    patch.object(adapter, "run_kag_build", return_value=rebuilt) as build_mock,
                    redirect_stdout(stdout),
                ):
                    adapter.real_response({"id": "build-repair", "method": "kag.build", "params": params})

                response = json.loads(stdout.getvalue().splitlines()[-1])
                self.assertEqual(response["type"], "result")
                self.assertTrue(response["data"]["repaired"])
                build_mock.assert_called_once()

    def test_real_build_rejects_invalid_receipt_before_config_and_health(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            runtime = workspace / ".knote" / "kag-runtime"
            key = "sync-invalid-receipt"
            path = adapter.build_receipt_path(runtime, key)
            path.parent.mkdir(parents=True)
            path.write_text("{not-json", encoding="utf-8")
            stdout = StringIO()
            req = {
                "id": "build-invalid-receipt",
                "method": "kag.build",
                "params": {
                    "workspace": str(workspace),
                    "runtime_dir": str(runtime),
                    "idempotency_key": key,
                },
            }

            with (
                patch.object(adapter, "select_config") as select_config_mock,
                patch.object(adapter, "check_real_health") as health_mock,
                redirect_stdout(stdout),
            ):
                adapter.real_response(req)

            response = json.loads(stdout.getvalue())
            self.assertEqual(response["type"], "error")
            self.assertIn("invalid KAG build idempotency receipt", response["error"])
            select_config_mock.assert_not_called()
            health_mock.assert_not_called()

    def test_real_build_validates_idempotency_key_before_config_and_health(self) -> None:
        stdout = StringIO()
        req = {
            "id": "build-invalid-key",
            "method": "kag.build",
            "params": {"workspace": str(Path.cwd()), "idempotency_key": " sync-invalid "},
        }

        with (
            patch.object(adapter, "select_config") as select_config_mock,
            patch.object(adapter, "check_real_health") as health_mock,
            redirect_stdout(stdout),
        ):
            adapter.real_response(req)

        response = json.loads(stdout.getvalue())
        self.assertEqual(response["type"], "error")
        self.assertIn("idempotency_key contains invalid whitespace", response["error"])
        select_config_mock.assert_not_called()
        health_mock.assert_not_called()

    def test_config_host_reads_literal_and_env_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "kag_config.yaml"
            config.write_text("project:\n  host_addr: http://127.0.0.1:9999\n", encoding="utf-8")
            self.assertEqual(adapter.config_host(config), "http://127.0.0.1:9999")

            with patch.dict(os.environ, {"KAG_PROJECT_HOST_ADDR": "http://env-host:8887"}):
                config.write_text("project:\n  host_addr: '{{ KAG_PROJECT_HOST_ADDR }}'\n", encoding="utf-8")
                self.assertEqual(adapter.config_host(config), "http://env-host:8887")
                config.write_text("project:\n  host_addr: !ENV KAG_PROJECT_HOST_ADDR\n", encoding="utf-8")
                self.assertEqual(adapter.config_host(config), "http://env-host:8887")

            with patch.dict(os.environ, {}, clear=True):
                config.write_text(
                    "project:\n  host_addr: \"{{ KAG_PROJECT_HOST_ADDR | default('http://fallback-host:8887') }}\"\n",
                    encoding="utf-8",
                )
                self.assertEqual(adapter.config_host(config), "http://fallback-host:8887")

            with patch.dict(os.environ, {"KAG_PROJECT_HOST_ADDR": "http://env-host:8887"}):
                config.write_text(
                    "project:\n  host_addr: \"{{ KAG_PROJECT_HOST_ADDR | default('http://fallback-host:8887') }}\"\n",
                    encoding="utf-8",
                )
                self.assertEqual(adapter.config_host(config), "http://env-host:8887")

    def test_check_real_health_prefers_config_host_override(self) -> None:
        seen: dict[str, str] = {}

        class FakeResponse:
            status = 200

            def __enter__(self) -> "FakeResponse":
                return self

            def __exit__(self, *args: object) -> None:
                return None

        def fake_urlopen(host: str, timeout: int) -> FakeResponse:
            seen["host"] = host
            seen["timeout"] = str(timeout)
            return FakeResponse()

        fake_kag = types.SimpleNamespace(__version__="0.8.0")
        req = {"id": "1", "method": "kag.query", "params": {"host": "http://bad-host:8887"}}
        with patch.dict(sys.modules, {"kag": fake_kag}), patch.object(adapter.urlrequest, "urlopen", fake_urlopen):
            data, err = adapter.check_real_health(req, "http://config-host:8887")

        self.assertIsNone(err)
        self.assertEqual(seen["host"], "http://config-host:8887")
        self.assertEqual(data["host"], "http://config-host:8887")

    def test_kag_stdout_is_not_emitted_as_adapter_stdout(self) -> None:
        stdout = StringIO()
        stderr = StringIO()

        def noisy_call() -> dict[str, bool]:
            print("human KAG progress")
            return {"ok": True}

        with redirect_stdout(stdout), redirect_stderr(stderr):
            data = adapter.run_capturing_stdout(noisy_call)

        self.assertEqual(data, {"ok": True})
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "human KAG progress\n")

    def test_parse_kag_build_summary(self) -> None:
        output = "\x1b[31mDone process 3 records, with 2 successfully processed and 1 failures encountered.\n"
        self.assertEqual(adapter.parse_build_summary(output), {"total": 3, "success": 2, "failures": 1})

    def test_failed_kag_build_summary_raises(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "KAG build failed"):
            adapter.ensure_successful_build_summary({"total": 2, "success": 0, "failures": 2})

    def test_missing_kag_build_summary_raises(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "parseable success summary"):
            adapter.ensure_successful_build_summary(None)

    def test_solver_falls_back_to_async_pipeline(self) -> None:
        class Base:
            def invoke(self, query: str) -> str:
                raise NotImplementedError("invoke not implemented yet.")

            async def ainvoke(self, query: str) -> str:
                raise NotImplementedError("ainvoke not implemented yet.")

        class AsyncOnly(Base):
            async def ainvoke(self, query: str) -> str:
                return "async answer: " + query

        self.assertEqual(adapter.run_solver_pipeline(AsyncOnly(), Base, "q"), "async answer: q")

    def test_fake_build_writes_corpus_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "sources").mkdir()
            (workspace / "sources" / "intro.md").write_text("# Intro\n\nknote is local-first.", encoding="utf-8")
            runtime_dir = workspace / ".knote" / "kag-runtime"
            env = os.environ.copy()
            env["KNOTE_KAG_FAKE"] = "1"
            req = {
                "id": "2",
                "method": "kag.build",
                "params": {"workspace": str(workspace), "runtime_dir": str(runtime_dir)},
            }
            proc = subprocess.run(
                [sys.executable, str(ADAPTER_PATH)],
                input=json.dumps(req) + "\n",
                text=True,
                capture_output=True,
                cwd=ROOT,
                env=env,
                check=True,
            )
            lines = [json.loads(line) for line in proc.stdout.splitlines()]
            self.assertEqual(lines[-1]["type"], "result")
            self.assertEqual(lines[-1]["data"]["documents"], 1)
            self.assertTrue(Path(lines[-1]["data"]["corpus_path"]).exists())

    def test_fake_build_accepts_explicit_corpus(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            runtime_dir = workspace / ".knote" / "kag-runtime"
            env = os.environ.copy()
            env["KNOTE_KAG_FAKE"] = "1"
            req = {
                "id": "2",
                "method": "kag.build",
                "params": {
                    "workspace": str(workspace),
                    "runtime_dir": str(runtime_dir),
                    "corpus": [
                        {
                            "id": "remote-1",
                            "name": "Remote note",
                            "content": "# Remote\n\ncontent from repository facade",
                            "source_path": "remote/source.md",
                        }
                    ],
                },
            }
            proc = subprocess.run(
                [sys.executable, str(ADAPTER_PATH)],
                input=json.dumps(req) + "\n",
                text=True,
                capture_output=True,
                cwd=ROOT,
                env=env,
                check=True,
            )
            lines = [json.loads(line) for line in proc.stdout.splitlines()]
            self.assertEqual(lines[-1]["type"], "result")
            self.assertEqual(lines[-1]["data"]["documents"], 1)
            corpus = json.loads(Path(lines[-1]["data"]["corpus_path"]).read_text(encoding="utf-8"))
            self.assertEqual(corpus[0]["id"], "remote-1")
            self.assertEqual(corpus[0]["source_path"], "remote/source.md")


if __name__ == "__main__":
    unittest.main()
