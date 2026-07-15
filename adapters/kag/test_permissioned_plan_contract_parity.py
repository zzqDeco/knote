from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "permissioned-plan-contract.json"
ADAPTER_PATH = ROOT / "adapters" / "kag" / "knote_kag_adapter.py"
FIXTURE_FIELDS = {
    "predicate_allowlist_version",
    "predicate_keys",
    "resource_kind_allowlist_version",
    "resource_kinds",
}

SPEC = importlib.util.spec_from_file_location("knote_kag_adapter", ADAPTER_PATH)
adapter = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(adapter)


class PermissionedPlanContractParityTest(unittest.TestCase):
    def test_restricted_plan_allowlists_match_shared_contract(self) -> None:
        fixture = self.load_fixture()

        self.require_exact_version(
            fixture,
            "predicate_allowlist_version",
            adapter.CLAIM_PREDICATE_ALLOWLIST_VERSION,
        )
        self.require_exact_version(
            fixture,
            "resource_kind_allowlist_version",
            adapter.GRAPH_RESOURCE_KIND_ALLOWLIST_VERSION,
        )
        self.require_exact_values(
            fixture,
            "predicate_keys",
            sorted(adapter.SUPPORTED_CLAIM_PREDICATE_KEYS),
        )
        self.require_exact_values(
            fixture,
            "resource_kinds",
            sorted(adapter.GRAPH_RESOURCE_KINDS),
        )

    def load_fixture(self) -> dict[str, object]:
        try:
            raw_fixture = FIXTURE_PATH.read_text(encoding="utf-8")
        except OSError as exc:
            self.fail(f"cannot read permissioned plan contract fixture ({type(exc).__name__})")
        try:
            fixture = json.loads(raw_fixture)
        except json.JSONDecodeError as exc:
            self.fail(
                "permissioned plan contract fixture is invalid JSON "
                f"at line {exc.lineno}, column {exc.colno}"
            )
        if not isinstance(fixture, dict):
            self.fail("permissioned plan contract fixture must be a JSON object")

        fixture_fields = set(fixture)
        if fixture_fields != FIXTURE_FIELDS:
            self.fail(
                "permissioned plan contract fixture field mismatch "
                f"(missing_count={len(FIXTURE_FIELDS - fixture_fields)}, "
                f"unexpected_count={len(fixture_fields - FIXTURE_FIELDS)})"
            )
        return fixture

    def require_exact_version(
        self, fixture: dict[str, object], field: str, adapter_version: int
    ) -> None:
        fixture_version = fixture[field]
        if type(fixture_version) is not int:
            self.fail(f"{field} fixture value must be an integer")
        if fixture_version != adapter_version:
            self.fail(
                f"{field} mismatch (fixture={fixture_version}, adapter={adapter_version})"
            )

    def require_exact_values(
        self, fixture: dict[str, object], field: str, adapter_values: list[str]
    ) -> None:
        fixture_values = fixture[field]
        if not isinstance(fixture_values, list):
            self.fail(f"{field} fixture value must be an array")
        for index, value in enumerate(fixture_values):
            if not isinstance(value, str):
                self.fail(f"{field} fixture has a non-string value at index {index}")
        for index in range(1, len(fixture_values)):
            if fixture_values[index - 1] >= fixture_values[index]:
                self.fail(
                    f"{field} fixture is not strictly sorted at index {index} "
                    "(values omitted)"
                )

        limit = min(len(fixture_values), len(adapter_values))
        for index in range(limit):
            if fixture_values[index] != adapter_values[index]:
                self.fail(
                    f"{field} mismatch at index {index} "
                    f"(values omitted; fixture_count={len(fixture_values)}, "
                    f"adapter_count={len(adapter_values)})"
                )
        if len(fixture_values) != len(adapter_values):
            self.fail(
                f"{field} count mismatch after index {limit} "
                f"(values omitted; fixture_count={len(fixture_values)}, "
                f"adapter_count={len(adapter_values)})"
            )


if __name__ == "__main__":
    unittest.main()
