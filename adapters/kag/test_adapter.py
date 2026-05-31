import json
import os
import subprocess
import sys
import tempfile
import unittest
import importlib.util
from pathlib import Path


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
            self.assertIn("host_addr: http://127.0.0.1:8887", text)
            self.assertIn('id: "7"', text)
            self.assertIn("namespace: KnoteTest", text)
            self.assertIn("scanner:\n    type: json_scanner", text)

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


if __name__ == "__main__":
    unittest.main()
