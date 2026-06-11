import json
import os
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
            self.assertIn('api_key: "local:key"', text)
            self.assertIn('model: "gpt-5.3-codex-spark"', text)
            self.assertIn('type: "mock"', text)
            self.assertIn("vector_dimensions: 256", text)

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
