"""Regression guards for the Red Night runtime isolation boundary."""

from __future__ import annotations

from pathlib import Path
import tomllib
import unittest

from nightrecon.edition_policy import (
    EDITIONS,
    EditionRouteError,
    available_commands,
    edition_name,
)


ROOT = Path(__file__).resolve().parents[1]


class RedRuntimeBoundaryTests(unittest.TestCase):
    def test_red_distribution_declares_current_legacy_runtime_dependency(self) -> None:
        """Keep the temporary coupling explicit until package extraction replaces it."""
        payload = tomllib.loads(
            (ROOT / "packages" / "red-night" / "pyproject.toml").read_text(encoding="utf-8")
        )
        dependencies = payload["project"]["dependencies"]
        self.assertEqual(dependencies, ["nightrecon==0.31.0"])

    def test_red_app_entrypoint_is_a_thin_adapter(self) -> None:
        source = (
            ROOT / "packages" / "red-night" / "red_night_app" / "__init__.py"
        ).read_text(encoding="utf-8")
        self.assertIn("from nightrecon.red_night import main as run_red_night", source)
        self.assertNotIn("nightrecon.cli", source)

    def test_policy_module_has_no_execution_imports(self) -> None:
        source = (ROOT / "nightrecon" / "edition_policy.py").read_text(encoding="utf-8")
        forbidden = (
            "nightrecon.cli",
            "socket",
            "requests",
            "playwright",
            "paramiko",
            "impacket",
            "pywinrm",
        )
        for name in forbidden:
            with self.subTest(name=name):
                self.assertNotIn(name, source)

    def test_red_policy_is_fail_closed_and_deterministic(self) -> None:
        commands = available_commands("red")
        self.assertEqual(commands, tuple(sorted(commands)))
        self.assertIn("scan", commands)
        self.assertIn("identity", commands)
        self.assertNotIn("unknown-command", commands)
        with self.assertRaisesRegex(EditionRouteError, "Unknown NightRecon edition"):
            available_commands("not-a-night")

    def test_catalog_comes_from_the_shared_policy(self) -> None:
        self.assertEqual(edition_name("red"), "Red Night")
        self.assertEqual([item.slug for item in EDITIONS], [
            "white", "blue", "red", "purple", "black",
        ])

    def test_gateway_consumes_policy_but_remains_execution_adapter(self) -> None:
        source = (ROOT / "nightrecon" / "edition_gateway.py").read_text(encoding="utf-8")
        self.assertIn("from nightrecon.edition_policy import", source)
        self.assertIn("from nightrecon.cli import main as legacy_main", source)
        self.assertNotIn("_COMMANDS =", source)


if __name__ == "__main__":
    unittest.main()
