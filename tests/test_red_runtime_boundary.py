"""Regression guard for the pre-extraction Red Night runtime boundary."""

from __future__ import annotations

from pathlib import Path
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RedRuntimeBoundaryTests(unittest.TestCase):
    def test_red_distribution_declares_current_legacy_runtime_dependency(self) -> None:
        """Keep the temporary coupling explicit until the extraction replaces it."""
        payload = tomllib.loads(
            (ROOT / "packages" / "red-night" / "pyproject.toml").read_text(encoding="utf-8")
        )
        dependencies = payload["project"]["dependencies"]
        self.assertEqual(dependencies, ["nightrecon==0.31.0"])

    def test_red_app_entrypoint_is_a_thin_adapter(self) -> None:
        """The separate app must not grow direct engine imports during extraction."""
        source = (
            ROOT / "packages" / "red-night" / "red_night_app" / "__init__.py"
        ).read_text(encoding="utf-8")
        self.assertIn("from nightrecon.red_night import main as run_red_night", source)
        self.assertNotIn("nightrecon.cli", source)

    def test_red_launcher_routes_through_the_fail_closed_gateway(self) -> None:
        source = (ROOT / "nightrecon" / "red_night.py").read_text(encoding="utf-8")
        self.assertIn("run_edition_cli", source)
        self.assertIn('run_edition_cli("red", arguments)', source)


if __name__ == "__main__":
    unittest.main()
