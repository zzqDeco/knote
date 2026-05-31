#!/usr/bin/env python3
"""Small PTY smoke driver for the knote Bubble Tea TUI."""

from __future__ import annotations

import argparse
import os
import re
import select
import signal
import sys
import time
from pathlib import Path


ANSI_RE = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"
    r"|\x1b\][^\x07]*(?:\x07|\x1b\\)"
    r"|\x1b[()][A-Za-z0-9]"
    r"|\x1b[=>?]"
)


class PTYDriver:
    def __init__(self, cmd: list[str], env: dict[str, str], cwd: Path) -> None:
        pid, master = os.forkpty()
        if pid == 0:
            try:
                os.chdir(cwd)
                os.execvpe(cmd[0], cmd, env)
            except Exception as exc:
                os.write(2, f"exec failed: {exc}\n".encode("utf-8"))
                os._exit(127)
        self.pid = pid
        self.raw = bytearray()
        self.offset = 0
        self.returncode: int | None = None
        self.master = master

    def close(self) -> None:
        if self.poll() is None:
            try:
                os.write(self.master, b"\x03")
                self.wait(timeout=3)
            except Exception:
                os.kill(self.pid, signal.SIGTERM)
                try:
                    self.wait(timeout=2)
                except TimeoutError:
                    os.kill(self.pid, signal.SIGKILL)
                    self.wait(timeout=2)
        os.close(self.master)

    def poll(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        pid, status = os.waitpid(self.pid, os.WNOHANG)
        if pid == 0:
            return None
        if os.WIFEXITED(status):
            self.returncode = os.WEXITSTATUS(status)
        elif os.WIFSIGNALED(status):
            self.returncode = -os.WTERMSIG(status)
        else:
            self.returncode = status
        return self.returncode

    def wait(self, timeout: float) -> int:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            code = self.poll()
            if code is not None:
                return code
            time.sleep(0.05)
        raise TimeoutError(f"process {self.pid} did not exit")

    def send(self, text: str) -> None:
        self.offset = len(self.clean())
        os.write(self.master, text.encode("utf-8"))

    def poke(self, text: str) -> None:
        os.write(self.master, text.encode("utf-8"))

    def clean(self) -> str:
        text = self.raw.decode("utf-8", errors="replace")
        text = ANSI_RE.sub("", text)
        text = text.replace("\r", "\n")
        return text

    def read_once(self, timeout: float) -> None:
        ready, _, _ = select.select([self.master], [], [], timeout)
        if not ready:
            return
        try:
            chunk = os.read(self.master, 65536)
        except OSError:
            return
        if chunk:
            self.raw.extend(chunk)

    def expect(self, *patterns: str, timeout: float = 20) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.read_once(0.1)
            window = self.clean()[self.offset :]
            if all(pattern in window for pattern in patterns):
                return
            code = self.poll()
            if code is not None:
                raise AssertionError(f"knote exited early with {code}\n{self.clean()[-4000:]}")
        raise AssertionError(f"timed out waiting for {patterns}\n{self.clean()[-4000:]}")


def latest_session_id(workspace: Path) -> str:
    session_dir = workspace / ".knote" / "sessions"
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        sessions = sorted(session_dir.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
        if sessions:
            return sessions[0].stem
        time.sleep(0.1)
    raise AssertionError(f"no session files found under {session_dir}")


def run_startup(driver: PTYDriver) -> None:
    driver.read_once(0.5)
    if not driver.clean():
        driver.poke("\r")
    driver.expect("session ready", "session sess_", "tasks", "kag fake", timeout=15)


def run_fake_mvp(driver: PTYDriver, workspace: Path) -> None:
    run_startup(driver)
    original_session = latest_session_id(workspace)

    driver.send("/build\r")
    driver.expect("Build knowledge", "Enter/y", timeout=10)
    driver.send("y")
    driver.expect("summaries: 1", timeout=30)

    driver.send("what is this knowledge base?\r")
    driver.expect("Fake KAG answer", timeout=20)

    driver.send("/diff\r")
    driver.expect("Untracked knote file", "artifacts/", timeout=20)

    driver.send("/commit acceptance build\r")
    driver.expect("Commit knowledge", timeout=10)
    driver.send("y")
    driver.expect("files changed", timeout=20)

    driver.send("/diff\r")
    driver.expect("No diff.", timeout=20)

    driver.send("/new\r")
    driver.expect("knote ready", timeout=15)

    driver.send(f"/resume {original_session}\r")
    driver.expect("session resumed", timeout=20)

    driver.send("/eval\r")
    driver.expect("Run evaluation", timeout=10)
    driver.send("y")
    driver.expect("uncertainty: fake", timeout=30)

    driver.send("/commit acceptance eval\r")
    driver.expect("Commit knowledge", timeout=10)
    driver.send("y")
    driver.expect("files changed", timeout=20)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin")
    parser.add_argument("--go-run", action="store_true")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--scenario", choices=["startup", "fake-mvp"], required=True)
    args = parser.parse_args()
    if not args.go_run and not args.bin:
        parser.error("--bin is required unless --go-run is set")

    root = Path(__file__).resolve().parents[2]
    workspace = Path(args.workspace).resolve()
    env = os.environ.copy()
    env["TERM"] = "xterm-256color"
    env["KNOTE_KAG_FAKE"] = "1"

    if args.go_run:
        cmd = ["go", "run", "./cmd/knote", "--workspace", str(workspace)]
    else:
        cmd = [str(Path(args.bin).resolve()), "--workspace", str(workspace)]
    last_error: AssertionError | None = None
    for attempt in range(4):
        driver = PTYDriver(cmd, env=env, cwd=root)
        try:
            if args.scenario == "startup":
                run_startup(driver)
            elif args.scenario == "fake-mvp":
                run_fake_mvp(driver, workspace)
            return 0
        except AssertionError as exc:
            last_error = exc
            empty_first_frame = not driver.clean().strip()
            if attempt < 3 and empty_first_frame:
                time.sleep(1)
                continue
            raise
        finally:
            driver.close()
    if last_error is not None:
        raise last_error
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
