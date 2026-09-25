"""Tests for the persistent NightRecon asset inventory store."""

import json
import tempfile
import unittest
from pathlib import Path

from nightrecon.asset_inventory import (
    AssetInventory,
    AssetRecord,
    AssetServiceRecord,
)
from nightrecon.asset_inventory_store import AssetInventoryStore


class AssetInventoryStoreTests(unittest.TestCase):
    def test_missing_inventory_loads_as_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AssetInventoryStore(directory)

            self.assertEqual(
                store.load(),
                AssetInventory.empty(),
            )

    def test_inventory_round_trip_is_deterministic(self):
        inventory = AssetInventory(
            assets=(
                AssetRecord(
                    address="192.0.2.10",
                    first_seen="2026-09-24T10:00:00+00:00",
                    last_seen="2026-09-24T12:00:00+00:00",
                    last_checked_at="2026-09-24T12:00:00+00:00",
                    hostnames=("web.example.test",),
                    os_platform="Ubuntu",
                    os_family="Linux",
                    os_confidence="high",
                    os_evidence_count=2,
                    last_discovery_responsive=True,
                    discovery_methods=("tcp-connect",),
                    services=(
                        AssetServiceRecord(
                            port=443,
                            service="https",
                            product="nginx",
                            version="1.24.0",
                            protocol_version="1.1",
                            platform="Ubuntu",
                            fingerprint_source="http-server",
                            fingerprint_confidence="high",
                            tls_certificate_sha256="abc123",
                        ),
                    ),
                    source_session_ids=("session-1", "session-2"),
                ),
            ),
            updated_at="2026-09-24T12:00:00+00:00",
        )

        with tempfile.TemporaryDirectory() as directory:
            store = AssetInventoryStore(directory)
            path = store.save(inventory)

            self.assertEqual(
                path,
                Path(directory) / "assets.json",
            )
            self.assertEqual(
                store.load(),
                inventory,
            )
            self.assertFalse(
                (Path(directory) / "assets.json.tmp").exists()
            )

    def test_v018_inventory_without_fingerprint_fields_still_loads(self):
        data = {
            "schema_version": 1,
            "updated_at": "2026-09-24T12:00:00+00:00",
            "assets": [
                {
                    "address": "192.0.2.10",
                    "first_seen": "2026-09-24T10:00:00+00:00",
                    "last_seen": "2026-09-24T12:00:00+00:00",
                    "last_checked_at": "2026-09-24T12:00:00+00:00",
                    "hostnames": [],
                    "last_discovery_responsive": None,
                    "discovery_methods": [],
                    "services": [
                        {
                            "port": 443,
                            "service": "https",
                            "product": "nginx",
                            "version": "1.24.0",
                            "tls_certificate_sha256": "abc123",
                        }
                    ],
                    "source_session_ids": [],
                }
            ],
        }

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "assets.json"
            path.write_text(
                json.dumps(data),
                encoding="utf-8",
            )

            inventory = AssetInventoryStore(directory).load()

        service = inventory.assets[0].services[0]
        self.assertEqual(service.protocol_version, "")
        self.assertEqual(service.platform, "")
        self.assertEqual(service.fingerprint_source, "")
        self.assertEqual(service.fingerprint_confidence, "")
        asset = inventory.assets[0]
        self.assertEqual(asset.os_platform, "")
        self.assertEqual(asset.os_family, "")
        self.assertEqual(asset.os_confidence, "")
        self.assertEqual(asset.os_candidates, ())
        self.assertEqual(asset.os_evidence_count, 0)

    def test_malformed_inventory_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "assets.json"
            path.write_text(
                "{not-json",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                ValueError,
                "Invalid asset inventory JSON",
            ):
                AssetInventoryStore(directory).load()

    def test_unsupported_schema_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "assets.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 999,
                        "updated_at": "",
                        "assets": [],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                ValueError,
                "Unsupported asset inventory schema version",
            ):
                AssetInventoryStore(directory).load()


if __name__ == "__main__":
    unittest.main()
