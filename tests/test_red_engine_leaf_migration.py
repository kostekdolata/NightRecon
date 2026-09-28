"""Regression tests for physical Red engine module migration."""

from __future__ import annotations

import importlib
from pathlib import Path
import unittest

import nightrecon.api_models as legacy_api_models
import nightrecon.graph_models as legacy_graph_models
import nightrecon.infrastructure_models as legacy_infrastructure_models
import nightrecon.service_fingerprint as legacy_service_fingerprint
import nightrecon.software_identity as legacy_software_identity
from nightrecon.red_ownership import RED_MIGRATED_ENGINE_MODULES
from nightrecon_red_engine import MIGRATED_MODULES
from nightrecon_red_engine import api_models
from nightrecon_red_engine import graph_models
from nightrecon_red_engine import infrastructure_models
from nightrecon_red_engine import service_fingerprint
from nightrecon_red_engine import software_identity


ROOT = Path(__file__).resolve().parents[1]
BATCH_C_RUNTIME_ALIASES = frozenset({
    "discovery_report",
    "host_discovery",
    "ports",
    "resolver",
    "service_probe",
    "session",
    "tcp_scanner",
    "tls_detection",
})


class RedEngineLeafMigrationTests(unittest.TestCase):
    def test_migration_manifest_has_one_source_of_truth(self) -> None:
        from nightrecon.red_ownership import RED_MODULE_GROUPS

        self.assertEqual(set(RED_MIGRATED_ENGINE_MODULES), set(MIGRATED_MODULES))
        self.assertTrue(set(RED_MODULE_GROUPS["web"]).issubset(MIGRATED_MODULES))
        self.assertTrue(set(RED_MODULE_GROUPS["api"]).issubset(MIGRATED_MODULES))
        self.assertTrue(set(RED_MODULE_GROUPS["checks"]).issubset(MIGRATED_MODULES))
        self.assertIn("host_discovery", MIGRATED_MODULES)
        self.assertIn("service_detection", MIGRATED_MODULES)
        self.assertIn("os_fingerprint", MIGRATED_MODULES)
        self.assertIn("infrastructure_ssh", MIGRATED_MODULES)
        self.assertIn("infrastructure_report", MIGRATED_MODULES)
        self.assertIn("vulnerability_intelligence", MIGRATED_MODULES)
        self.assertIn("threat_context", MIGRATED_MODULES)
        self.assertIn("asset_inventory", MIGRATED_MODULES)
        self.assertIn("storage", MIGRATED_MODULES)
        self.assertTrue(set(RED_MODULE_GROUPS["graph_identity"]).issubset(MIGRATED_MODULES))
        self.assertTrue(set(RED_MODULE_GROUPS["vulnerability"]).issubset(MIGRATED_MODULES))
        self.assertTrue(set(RED_MODULE_GROUPS["discovery"]).issubset(MIGRATED_MODULES))
        self.assertTrue(set(RED_MODULE_GROUPS["infrastructure"]).issubset(MIGRATED_MODULES))

    def test_legacy_imports_reexport_canonical_red_objects(self) -> None:
        pairs = (
            (legacy_api_models.ApiInventory, api_models.ApiInventory),
            (legacy_graph_models.GraphNode, graph_models.GraphNode),
            (
                legacy_infrastructure_models.InfrastructureAction,
                infrastructure_models.InfrastructureAction,
            ),
            (
                legacy_service_fingerprint.ServiceFingerprint,
                service_fingerprint.ServiceFingerprint,
            ),
            (
                legacy_software_identity.SoftwareIdentity,
                software_identity.SoftwareIdentity,
            ),
        )
        for legacy, canonical in pairs:
            with self.subTest(name=canonical.__name__):
                self.assertIs(legacy, canonical)

    def test_batch_c_runtime_legacy_modules_alias_canonical_modules(self) -> None:
        for module in BATCH_C_RUNTIME_ALIASES:
            with self.subTest(module=module):
                legacy = importlib.import_module(f"nightrecon.{module}")
                canonical = importlib.import_module(f"nightrecon_red_engine.{module}")
                self.assertIs(legacy, canonical)

    def test_legacy_files_are_compatibility_only(self) -> None:
        for module in MIGRATED_MODULES:
            source = (ROOT / "nightrecon" / f"{module}.py").read_text(encoding="utf-8")
            self.assertIn(f"nightrecon_red_engine.{module}", source)
            self.assertNotIn("@dataclass", source)
            self.assertNotIn("class ", source)

    def test_canonical_sources_live_only_in_red_engine_package(self) -> None:
        engine_root = ROOT / "packages" / "red-engine" / "nightrecon_red_engine"
        for module in MIGRATED_MODULES:
            with self.subTest(module=module):
                source = engine_root / f"{module}.py"
                self.assertTrue(source.is_file())
                text = source.read_text(encoding="utf-8")
                self.assertGreater(len(text), 100)
                self.assertNotIn("from nightrecon.", text)
                self.assertNotIn("import nightrecon.", text)


if __name__ == "__main__":
    unittest.main()
