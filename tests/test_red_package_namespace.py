"""Tests for the Red Night engine package namespace."""

from __future__ import annotations

from pathlib import Path
import unittest

import nightrecon.host_discovery as legacy_host_discovery
import nightrecon_red_engine as engine


ROOT = Path(__file__).resolve().parents[1]


class RedPackageNamespaceTests(unittest.TestCase):
    def test_namespace_is_distinct_from_legacy_package(self) -> None:
        self.assertEqual(engine.NAMESPACE, "nightrecon_red_engine")
        self.assertEqual(engine.LEGACY_NAMESPACE, "nightrecon")

    def test_migrated_red_module_resolves_from_engine_package(self) -> None:
        import nightrecon.software_identity as legacy
        from nightrecon_red_engine import software_identity

        self.assertTrue(engine.is_migrated_module("software_identity"))
        self.assertIs(engine.existing_module("software_identity"), software_identity)
        self.assertIs(legacy.SoftwareIdentity, software_identity.SoftwareIdentity)

    def test_migrated_runtime_module_preserves_legacy_module_identity(self) -> None:
        from nightrecon_red_engine import host_discovery

        self.assertTrue(engine.is_migrated_module("host_discovery"))
        self.assertIs(engine.existing_module("host_discovery"), host_discovery)
        self.assertIs(legacy_host_discovery, host_discovery)

    def test_unmigrated_module_is_rejected_by_engine_resolver(self) -> None:
        self.assertFalse(engine.is_migrated_module("vulnerability_intelligence"))
        with self.assertRaisesRegex(ValueError, "not migrated to Red engine"):
            engine.existing_module("vulnerability_intelligence")

    def test_engine_namespace_has_no_legacy_runtime_dependency(self) -> None:
        namespace = ROOT / "packages" / "red-engine" / "nightrecon_red_engine"
        sources = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(namespace.glob("*.py"))
        )
        for forbidden in (
            "from nightrecon.",
            "import nightrecon.",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, sources)


if __name__ == "__main__":
    unittest.main()
