"""Regression tests for Red Night ownership assignment."""

from pathlib import Path
import unittest

from nightrecon.red_ownership import (
    RED_COMMANDS,
    RED_MODULE_GROUPS,
    RED_OPTIONAL_EXTRAS,
    SHARED_CORE_COMPATIBILITY_MODULES,
    red_modules,
)

ROOT = Path(__file__).resolve().parents[1]


class RedOwnershipTests(unittest.TestCase):
    def test_owned_modules_exist_without_duplicate_red_copies(self) -> None:
        modules = red_modules()
        self.assertEqual(modules, tuple(sorted(set(modules))))
        for module in modules:
            with self.subTest(module=module):
                self.assertTrue((ROOT / "nightrecon" / f"{module}.py").is_file())

    def test_existing_major_capability_groups_are_assigned_to_red(self) -> None:
        self.assertIn("host_discovery", RED_MODULE_GROUPS["discovery"])
        self.assertIn("web_crawl", RED_MODULE_GROUPS["web"])
        self.assertIn("api_execution", RED_MODULE_GROUPS["api"])
        self.assertIn("infrastructure_ssh", RED_MODULE_GROUPS["infrastructure"])
        self.assertIn("vulnerability_intelligence", RED_MODULE_GROUPS["vulnerability"])
        self.assertIn("assessment_engine", RED_MODULE_GROUPS["checks"])
        self.assertIn("graph_path_review", RED_MODULE_GROUPS["graph_identity"])

    def test_optional_runtime_dependencies_are_red_extras(self) -> None:
        self.assertEqual(
            set(RED_OPTIONAL_EXTRAS),
            {"browser", "api", "ad", "ssh", "smb", "winrm", "postgres", "mysql"},
        )

    def test_red_commands_cover_existing_assessment_surfaces(self) -> None:
        self.assertEqual(
            set(RED_COMMANDS),
            {"api", "assets", "checks", "crawl", "discover", "editions", "identity", "infra", "pentest", "run-all", "scan", "workspace"},
        )

    def test_shared_core_compatibility_modules_are_not_red_engines(self) -> None:
        owned = set(red_modules())
        self.assertTrue(set(SHARED_CORE_COMPATIBILITY_MODULES).isdisjoint(owned))


if __name__ == "__main__":
    unittest.main()
