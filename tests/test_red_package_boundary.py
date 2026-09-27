"""Tests for the future Red Night package dependency boundary."""

from __future__ import annotations

from pathlib import Path
import tomllib
import unittest

from nightrecon.edition_policy import available_commands
from nightrecon.red_package_boundary import audit_red_dependencies
from nightrecon.red_ownership import (
    RED_BASE_DEPENDENCIES,
    RED_COMMANDS,
    RED_ENGINE_FACADES,
    RED_LEGACY_BRIDGE_DEPENDENCY,
    RED_OPTIONAL_EXTRAS,
    red_package_modules,
)


ROOT = Path(__file__).resolve().parents[1]


class RedPackageBoundaryTests(unittest.TestCase):
    def test_dependency_closure_has_no_unclassified_nightrecon_imports(self) -> None:
        audit = audit_red_dependencies(ROOT / "nightrecon")
        self.assertEqual(audit.unresolved_edges, ())

    def test_red_command_manifest_matches_fail_closed_gateway_policy(self) -> None:
        self.assertEqual(set(RED_COMMANDS), set(available_commands("red")))

    def test_red_package_manifest_points_to_existing_modules(self) -> None:
        for module in red_package_modules():
            with self.subTest(module=module):
                self.assertTrue((ROOT / "nightrecon" / f"{module}.py").is_file())

    def test_engine_facades_are_thin_and_do_not_duplicate_engine_code(self) -> None:
        for module in RED_ENGINE_FACADES:
            source = (ROOT / "nightrecon" / f"{module}.py").read_text(encoding="utf-8")
            self.assertNotIn("socket.socket", source)
            self.assertNotIn("ThreadPoolExecutor", source)
            self.assertNotIn("def scan_tcp_port", source)
            self.assertNotIn("def detect_service", source)

    def test_red_package_metadata_matches_dependency_manifest(self) -> None:
        payload = tomllib.loads(
            (ROOT / "packages" / "red-night" / "pyproject.toml").read_text(
                encoding="utf-8"
            )
        )
        dependencies = set(payload["project"]["dependencies"])
        self.assertIn(RED_LEGACY_BRIDGE_DEPENDENCY, dependencies)
        self.assertTrue(set(RED_BASE_DEPENDENCIES).issubset(dependencies))

        optional = payload["project"]["optional-dependencies"]
        for name, expected in RED_OPTIONAL_EXTRAS.items():
            with self.subTest(extra=name):
                self.assertEqual(tuple(optional[name]), expected)

        expected_all = {
            dependency
            for dependencies_for_extra in RED_OPTIONAL_EXTRAS.values()
            for dependency in dependencies_for_extra
        }
        self.assertEqual(set(optional["all"]), expected_all)


if __name__ == "__main__":
    unittest.main()
