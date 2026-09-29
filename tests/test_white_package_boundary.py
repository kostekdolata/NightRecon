"""Tests for the independent White Night package boundary."""

from __future__ import annotations

import ast
from pathlib import Path
import tomllib
import unittest

from nightrecon_shared_core.editions import available_commands
from nightrecon_white_engine.capabilities import (
    WHITE_ACTIVE_COMMANDS,
    WHITE_EDITION_SLUG,
    WHITE_FOUNDATION_CAPABILITIES,
    WHITE_OWNED_COMMANDS,
)


ROOT = Path(__file__).resolve().parents[1]
ENGINE_ROOT = ROOT / "packages" / "white-engine" / "nightrecon_white_engine"
APP_ROOT = ROOT / "packages" / "white-night" / "white_night_app"


def imported_roots(path: Path) -> set[str]:
    roots: set[str] = set()
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".", 1)[0])
    return roots


class WhitePackageBoundaryTests(unittest.TestCase):
    def test_white_manifest_matches_fail_closed_shared_core_policy(self) -> None:
        self.assertEqual(WHITE_EDITION_SLUG, "white")
        self.assertEqual(WHITE_OWNED_COMMANDS, available_commands("white"))
        self.assertEqual(WHITE_OWNED_COMMANDS, ("approval", "editions", "policy"))
        self.assertEqual(WHITE_ACTIVE_COMMANDS, ())

    def test_foundation_declares_all_required_deployment_targets(self) -> None:
        self.assertEqual(
            set(WHITE_FOUNDATION_CAPABILITIES),
            {
                "independent-package-boundary",
                "shared-core-policy-consumer",
                "standalone-deployment-target",
                "composed-stack-deployment-target",
                "live-usb-deployment-target",
                "deterministic-policy-compiler",
                "approval-workflow-engine",
            },
        )

    def test_white_engine_metadata_has_only_shared_core_runtime_dependency(self) -> None:
        payload = tomllib.loads(
            (ROOT / "packages" / "white-engine" / "pyproject.toml").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(payload["project"]["name"], "nightrecon-white-engine")
        self.assertEqual(payload["project"]["version"], "0.1.0a5")
        self.assertEqual(
            set(payload["project"]["dependencies"]),
            {"nightrecon-shared-core==0.42.0"},
        )
        self.assertEqual(
            set(payload["tool"]["setuptools"]["packages"]["find"]["include"]),
            {"nightrecon_white_engine*"},
        )

    def test_white_app_metadata_has_no_other_night_or_legacy_dependency(self) -> None:
        payload = tomllib.loads(
            (ROOT / "packages" / "white-night" / "pyproject.toml").read_text(
                encoding="utf-8"
            )
        )
        dependencies = set(payload["project"]["dependencies"])
        self.assertEqual(payload["project"]["name"], "nightrecon-white-night")
        self.assertEqual(payload["project"]["version"], "0.1.0a5")
        self.assertEqual(
            dependencies,
            {
                "nightrecon-shared-core==0.42.0",
                "nightrecon-white-engine==0.1.0a5",
            },
        )
        forbidden = (
            "nightrecon-red",
            "nightrecon-blue",
            "nightrecon-purple",
            "nightrecon-black",
            "nightrecon==",
        )
        for dependency in dependencies:
            self.assertFalse(dependency.startswith(forbidden), dependency)
        self.assertEqual(
            set(payload["tool"]["setuptools"]["packages"]["find"]["include"]),
            {"white_night_app*"},
        )
        self.assertEqual(
            payload["project"]["scripts"],
            {"white-night-app": "white_night_app:main"},
        )

    def test_engine_source_does_not_import_another_night_or_legacy_runtime(self) -> None:
        forbidden_roots = {
            "nightrecon",
            "nightrecon_red_engine",
            "nightrecon_blue_engine",
            "nightrecon_purple_engine",
            "nightrecon_black_engine",
        }
        for path in ENGINE_ROOT.glob("*.py"):
            with self.subTest(path=path.name):
                self.assertTrue(imported_roots(path).isdisjoint(forbidden_roots))

    def test_app_source_only_routes_to_white_engine(self) -> None:
        forbidden_roots = {
            "nightrecon",
            "nightrecon_red_engine",
            "nightrecon_blue_engine",
            "nightrecon_purple_engine",
            "nightrecon_black_engine",
        }
        for path in APP_ROOT.glob("*.py"):
            with self.subTest(path=path.name):
                self.assertTrue(imported_roots(path).isdisjoint(forbidden_roots))

    def test_white_engine_contains_no_network_or_process_execution_surface(self) -> None:
        forbidden_text = (
            "socket.",
            "subprocess.",
            "requests.",
            "urllib.request",
            "http.client",
            "paramiko",
            "impacket",
            "playwright",
        )
        for path in ENGINE_ROOT.glob("*.py"):
            source = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                for marker in forbidden_text:
                    self.assertNotIn(marker, source)


if __name__ == "__main__":
    unittest.main()
