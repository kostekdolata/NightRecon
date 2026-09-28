"""Regression tests for the first physical Red engine module migration."""

from __future__ import annotations

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


class RedEngineLeafMigrationTests(unittest.TestCase):
    def test_migration_manifest_has_one_source_of_truth(self) -> None:
        self.assertEqual(set(RED_MIGRATED_ENGINE_MODULES), set(MIGRATED_MODULES))
        self.assertEqual(
            set(MIGRATED_MODULES),
            {
                "api_models",
                "graph_models",
                "infrastructure_models",
                "service_fingerprint",
                "software_identity",
            },
        )

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
                self.assertGreater(len(source.read_text(encoding="utf-8")), 100)


if __name__ == "__main__":
    unittest.main()
