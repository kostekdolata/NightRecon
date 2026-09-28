"""Regression guards for the Red Night runtime isolation boundary."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest

from nightrecon.authorization_policy import Scope, TargetType, parse_target
from nightrecon.edition_policy import (
    EDITIONS,
    EditionRouteError,
    available_commands,
    edition_name,
)
from nightrecon.red_ownership import (
    RED_BASE_DEPENDENCIES,
    RED_ENGINE_DISTRIBUTION_DEPENDENCY,
    RED_LEGACY_BRIDGE_DEPENDENCY,
)


ROOT = Path(__file__).resolve().parents[1]


class RedRuntimeBoundaryTests(unittest.TestCase):
    def test_red_distribution_declares_current_legacy_runtime_dependency(self) -> None:
        """Keep the temporary coupling explicit until package extraction replaces it."""
        payload = tomllib.loads(
            (ROOT / "packages" / "red-night" / "pyproject.toml").read_text(encoding="utf-8")
        )
        dependencies = set(payload["project"]["dependencies"])
        self.assertEqual(
            dependencies,
            set(RED_BASE_DEPENDENCIES)
            | {RED_LEGACY_BRIDGE_DEPENDENCY, RED_ENGINE_DISTRIBUTION_DEPENDENCY},
        )

    def test_root_distribution_declares_red_engine_dependency(self) -> None:
        payload = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        self.assertIn(
            RED_ENGINE_DISTRIBUTION_DEPENDENCY,
            payload["project"]["dependencies"],
        )

    def test_red_app_entrypoint_is_a_thin_adapter(self) -> None:
        source = (
            ROOT / "packages" / "red-night" / "red_night_app" / "__init__.py"
        ).read_text(encoding="utf-8")
        self.assertIn("from nightrecon_red_engine.red_cli import main as run_red_night", source)
        self.assertNotIn("nightrecon.red_night", source)\n        self.assertNotIn("nightrecon.cli", source)

    def test_red_engine_cli_has_no_legacy_runtime_imports(self) -> None:
        source = (
            ROOT / "packages" / "red-engine" /
            "nightrecon_red_engine" / "red_cli.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("from nightrecon.", source)
        self.assertNotIn("import nightrecon.", source)
        self.assertIn("from nightrecon_shared_core.editions import", source)
        self.assertIn("from nightrecon_shared_core.authorization import", source)

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
        self.assertIn("workspace", commands)
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
        self.assertIn("nightrecon.red_workspace_cli", source)

    def test_authorization_policy_has_no_execution_imports(self) -> None:
        source = (ROOT / "nightrecon" / "authorization_policy.py").read_text(
            encoding="utf-8"
        )
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

    def test_legacy_target_and_scope_modules_reexport_shared_types(self) -> None:
        from nightrecon.scope import Scope as LegacyScope
        from nightrecon.targets import TargetType as LegacyTargetType
        from nightrecon.targets import parse_target as legacy_parse_target

        self.assertIs(LegacyScope, Scope)
        self.assertIs(LegacyTargetType, TargetType)
        self.assertIs(legacy_parse_target, parse_target)

    def test_scope_remains_explicit_and_fail_closed(self) -> None:
        scope = Scope.from_values(["192.0.2.0/24", "example.test"])
        self.assertTrue(scope.is_authorized(parse_target("192.0.2.10")))
        self.assertTrue(scope.is_authorized(parse_target("EXAMPLE.TEST")))
        self.assertFalse(scope.is_authorized(parse_target("198.51.100.10")))
        self.assertFalse(scope.is_authorized(parse_target("other.example.test")))
        with self.assertRaisesRegex(ValueError, "At least one scope rule"):
            Scope.from_values([])

    def test_identity_envelope_requires_explicit_engagement_id(self) -> None:
        with tempfile.TemporaryDirectory(prefix="red-identity-envelope-") as directory:
            snapshot = Path(directory) / "directory.json"
            snapshot.write_text(
                '{"schema_version":1,"entries":[]}',
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "nightrecon.red_night",
                    "identity",
                    "import",
                    str(snapshot),
                    "--source-id",
                    "fixture",
                    "--export-envelope",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("--engagement-id is required", completed.stderr)

    def test_red_engine_facades_do_not_duplicate_existing_engines(self) -> None:
        expectations = {
            "red_host_discovery.py": "from nightrecon.host_discovery import",
            "red_tcp_scanner.py": "from nightrecon.tcp_scanner import",
            "red_service_detection.py": "from nightrecon.service_detection import",
        }
        for filename, expected_import in expectations.items():
            source = (ROOT / "nightrecon" / filename).read_text(encoding="utf-8")
            self.assertIn(expected_import, source)
            self.assertNotIn("socket.socket", source)
            self.assertNotIn("ThreadPoolExecutor", source)

    def test_legacy_cli_consumes_red_discovery_engines_directly(self) -> None:
        source = (ROOT / "nightrecon" / "cli.py").read_text(encoding="utf-8")
        self.assertIn("from nightrecon.red_host_discovery import", source)
        self.assertIn("from nightrecon.red_tcp_scanner import", source)
        self.assertNotIn("from nightrecon.host_discovery import", source)
        self.assertNotIn("from nightrecon.tcp_scanner import", source)
        self.assertIn("from nightrecon.red_service_detection import", source)
        self.assertNotIn("from nightrecon.service_detection import", source)

    def test_shared_workspace_has_no_night_runtime_import(self) -> None:
        source = (
            ROOT / "packages" / "shared-core" /
            "nightrecon_shared_core" / "workspace.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("from nightrecon.", source)
        self.assertNotIn("import nightrecon.", source)
        for forbidden in ("socket", "requests", "playwright", "paramiko", "impacket"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
