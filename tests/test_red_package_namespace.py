"""Tests for the Red Night package namespace skeleton."""

from __future__ import annotations

import importlib
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
RED_PACKAGE_ROOT = ROOT / "packages" / "red-night"


class RedPackageNamespaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._path = str(RED_PACKAGE_ROOT)
        sys.path.insert(0, cls._path)
        cls.engine = importlib.import_module("nightrecon_red_engine")

    @classmethod
    def tearDownClass(cls) -> None:
        if sys.path and sys.path[0] == cls._path:
            sys.path.pop(0)
        for name in tuple(sys.modules):
            if name == "nightrecon_red_engine" or name.startswith("nightrecon_red_engine."):
                sys.modules.pop(name, None)

    def test_namespace_is_distinct_from_legacy_package(self) -> None:
        self.assertEqual(self.engine.NAMESPACE, "nightrecon_red_engine")
        self.assertEqual(self.engine.LEGACY_NAMESPACE, "nightrecon")

    def test_existing_red_module_resolves_without_copying_implementation(self) -> None:
        legacy = importlib.import_module("nightrecon.host_discovery")
        self.assertTrue(self.engine.is_red_owned_module("host_discovery"))
        self.assertIs(self.engine.existing_module("host_discovery"), legacy)

    def test_unowned_module_is_rejected(self) -> None:
        self.assertFalse(self.engine.is_red_owned_module("authorization_policy"))
        with self.assertRaisesRegex(ValueError, "not declared Red-owned"):
            self.engine.existing_module("authorization_policy")

    def test_namespace_source_contains_no_assessment_engine_implementation(self) -> None:
        namespace = RED_PACKAGE_ROOT / "nightrecon_red_engine"
        sources = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(namespace.glob("*.py"))
        )
        for forbidden in (
            "socket.socket",
            "ThreadPoolExecutor",
            "requests.",
            "playwright",
            "paramiko",
            "impacket",
            "scan_tcp_port(",
            "detect_service(",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, sources)


if __name__ == "__main__":
    unittest.main()
