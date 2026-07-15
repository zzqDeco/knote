"""Deterministic permissioned KAG provider for the built-binary smoke."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


CONTROL_ENV = "KNOTE_PERMISSIONED_BINARY_CONTROL"
STATS_ENV = "KNOTE_PERMISSIONED_BINARY_STATS"
SUBJECT_ENV = "KNOTE_PERMISSIONED_BINARY_SUBJECT_GRAPH_ID"
ANSWER_ENV = "KNOTE_PERMISSIONED_BINARY_PROVIDER_ANSWER"
EXPECTED_CONTENT_ENV = "KNOTE_PERMISSIONED_BINARY_EXPECTED_CONTENT"
FAILURE_SECRET_ENV = "KNOTE_PERMISSIONED_BINARY_PROVIDER_SECRET"


def _control() -> dict[str, Any]:
    path = Path(os.environ[CONTROL_ENV])
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("invalid provider control")
    return value


def _record(operation: str, mode: str) -> None:
    path = Path(os.environ[STATS_ENV])
    line = json.dumps(
        {"mode": mode, "operation": operation},
        sort_keys=True,
        separators=(",", ":"),
    )
    with path.open("a", encoding="utf-8") as stream:
        stream.write(line + "\n")


def _fail_if_requested(mode: str) -> None:
    if mode == "provider_failure":
        raise RuntimeError(os.environ[FAILURE_SECRET_ENV])


class Provider:
    def retrieve(self, request: dict[str, Any]) -> dict[str, Any]:
        mode = str(_control().get("mode", "success"))
        _record("retrieve", mode)
        _fail_if_requested(mode)
        if mode == "empty":
            return {"candidates": []}

        allowed = request.get("allowed_graph_object_ids")
        subject = os.environ[SUBJECT_ENV]
        if not isinstance(allowed, list) or subject not in allowed:
            return {"candidates": []}
        return {"candidates": [{"graph_object_id": subject, "score": 1.0}]}

    def generate(self, request: dict[str, Any]) -> dict[str, Any]:
        mode = str(_control().get("mode", "success"))
        _record("generate", mode)
        _fail_if_requested(mode)
        evidence = request.get("evidence")
        expected = os.environ[EXPECTED_CONTENT_ENV]
        if not isinstance(evidence, list) or not any(
            isinstance(item, dict) and item.get("content") == expected
            for item in evidence
        ):
            raise RuntimeError("provider evidence contract mismatch")
        return {"answer": os.environ[ANSWER_ENV]}


def create(_context: dict[str, Any]) -> Provider:
    return Provider()
