"""Tests for persistent NightRecon asset inventory and change tracking."""

import unittest

from nightrecon.asset_inventory import (
    AssetInventory,
    AssetRecord,
    AssetServiceRecord,
    apply_discovery_report,
    apply_scan_report,
)
from nightrecon.discovery_report import HostDiscoveryReport
from nightrecon.host_discovery import HostDiscoveryResult
from nightrecon.report import TcpScanReport
from nightrecon.service_detection import ServiceDetectionResult
from nightrecon.session import ScanSession
from nightrecon.software_identity import SoftwareIdentity
from nightrecon.targets import parse_target
from nightrecon.tcp_scanner import TcpPortResult


class AssetInventoryTests(unittest.TestCase):
    def test_responsive_discovery_creates_host_asset(self):
        session = ScanSession(
            session_id="discovery-1",
            created_at="2026-09-24T10:00:00+00:00",
            target="192.0.2.0/30",
            target_type="cidr",
            scope=("192.0.2.0/24",),
            status="created",
        )
        report = HostDiscoveryReport.create(
            session=session,
            ports_requested=(443,),
            max_hosts=16,
            results=(
                HostDiscoveryResult(
                    address="192.0.2.1",
                    responsive=True,
                    method="tcp-connect",
                    port=443,
                    observation="tcp-open",
                    hostname="host1.example.test",
                ),
                HostDiscoveryResult(
                    address="192.0.2.2",
                    responsive=False,
                    method="tcp-connect",
                    port=None,
                    observation="no-response",
                ),
            ),
        )

        update = apply_discovery_report(
            AssetInventory.empty(),
            report,
        )

        self.assertEqual(len(update.inventory.assets), 1)
        asset = update.inventory.assets[0]
        self.assertEqual(asset.address, "192.0.2.1")
        self.assertEqual(
            asset.hostnames,
            ("host1.example.test",),
        )
        self.assertEqual(
            asset.first_seen,
            "2026-09-24T10:00:00+00:00",
        )
        self.assertEqual(
            asset.last_seen,
            "2026-09-24T10:00:00+00:00",
        )
        self.assertEqual(
            asset.last_checked_at,
            "2026-09-24T10:00:00+00:00",
        )
        self.assertTrue(asset.last_discovery_responsive)
        self.assertEqual(
            asset.discovery_methods,
            ("tcp-connect",),
        )
        self.assertEqual(
            asset.source_session_ids,
            ("discovery-1",),
        )
        self.assertEqual(
            tuple(change.change_type for change in update.changes),
            ("new-asset",),
        )

    def test_unresponsive_discovery_does_not_erase_last_seen(self):
        existing = AssetInventory(
            assets=(
                AssetRecord(
                    address="192.0.2.1",
                    first_seen="2026-09-24T10:00:00+00:00",
                    last_seen="2026-09-24T10:00:00+00:00",
                    last_checked_at="2026-09-24T10:00:00+00:00",
                    last_discovery_responsive=True,
                    source_session_ids=("discovery-1",),
                ),
            ),
        )
        session = ScanSession(
            session_id="discovery-2",
            created_at="2026-09-24T11:00:00+00:00",
            target="192.0.2.0/30",
            target_type="cidr",
            scope=("192.0.2.0/24",),
            status="created",
        )
        report = HostDiscoveryReport.create(
            session=session,
            ports_requested=(443,),
            max_hosts=16,
            results=(
                HostDiscoveryResult(
                    address="192.0.2.1",
                    responsive=False,
                    method="tcp-connect",
                    port=None,
                    observation="no-response",
                ),
            ),
        )

        update = apply_discovery_report(existing, report)

        asset = update.inventory.assets[0]
        self.assertEqual(
            asset.last_seen,
            "2026-09-24T10:00:00+00:00",
        )
        self.assertEqual(
            asset.last_checked_at,
            "2026-09-24T11:00:00+00:00",
        )
        self.assertFalse(asset.last_discovery_responsive)
        self.assertEqual(
            asset.source_session_ids,
            ("discovery-1", "discovery-2"),
        )
        self.assertIn(
            "host-unresponsive",
            tuple(change.change_type for change in update.changes),
        )

    def test_scan_creates_service_and_software_inventory(self):
        software = SoftwareIdentity(
            product="nginx",
            version="1.24.0",
            source="http-server",
            evidence="nginx/1.24.0",
        )
        report = TcpScanReport(
            session_id="scan-1",
            created_at="2026-09-24T12:00:00+00:00",
            target="192.0.2.10",
            target_type="ipv4",
            scope=("192.0.2.0/24",),
            status="completed",
            resolved_addresses=("192.0.2.10",),
            ports_requested=(80, 443),
            results=(
                TcpPortResult(
                    address="192.0.2.10",
                    port=80,
                    is_open=True,
                    error_code=0,
                ),
                TcpPortResult(
                    address="192.0.2.10",
                    port=443,
                    is_open=False,
                    error_code=111,
                ),
            ),
            services=(
                ServiceDetectionResult(
                    address="192.0.2.10",
                    port=80,
                    service="http",
                    banner="",
                    software_identity=software,
                ),
            ),
        )

        update = apply_scan_report(
            AssetInventory.empty(),
            report,
        )

        asset = update.inventory.assets[0]
        self.assertEqual(asset.address, "192.0.2.10")
        self.assertEqual(
            asset.services,
            (
                AssetServiceRecord(
                    port=80,
                    service="http",
                    product="nginx",
                    version="1.24.0",
                ),
            ),
        )
        self.assertIn(
            "new-asset",
            tuple(change.change_type for change in update.changes),
        )
        self.assertIn(
            "port-opened",
            tuple(change.change_type for change in update.changes),
        )

    def test_scan_detects_port_and_software_changes(self):
        existing = AssetInventory(
            assets=(
                AssetRecord(
                    address="192.0.2.10",
                    first_seen="2026-09-24T10:00:00+00:00",
                    last_seen="2026-09-24T10:00:00+00:00",
                    last_checked_at="2026-09-24T10:00:00+00:00",
                    services=(
                        AssetServiceRecord(
                            port=80,
                            service="http",
                            product="nginx",
                            version="1.23.0",
                        ),
                        AssetServiceRecord(
                            port=443,
                            service="https",
                        ),
                    ),
                    source_session_ids=("scan-0",),
                ),
            ),
        )
        software = SoftwareIdentity(
            product="nginx",
            version="1.24.0",
            source="http-server",
            evidence="nginx/1.24.0",
        )
        report = TcpScanReport(
            session_id="scan-2",
            created_at="2026-09-24T13:00:00+00:00",
            target="192.0.2.10",
            target_type="ipv4",
            scope=("192.0.2.0/24",),
            status="completed",
            resolved_addresses=("192.0.2.10",),
            ports_requested=(80, 443, 8080),
            results=(
                TcpPortResult(
                    address="192.0.2.10",
                    port=80,
                    is_open=True,
                    error_code=0,
                ),
                TcpPortResult(
                    address="192.0.2.10",
                    port=443,
                    is_open=False,
                    error_code=111,
                ),
                TcpPortResult(
                    address="192.0.2.10",
                    port=8080,
                    is_open=True,
                    error_code=0,
                ),
            ),
            services=(
                ServiceDetectionResult(
                    address="192.0.2.10",
                    port=80,
                    service="http",
                    banner="",
                    software_identity=software,
                ),
                ServiceDetectionResult(
                    address="192.0.2.10",
                    port=8080,
                    service="http-alt",
                    banner="",
                ),
            ),
        )

        update = apply_scan_report(existing, report)

        asset = update.inventory.assets[0]
        self.assertEqual(
            tuple(service.port for service in asset.services),
            (80, 8080),
        )
        self.assertEqual(asset.services[0].version, "1.24.0")

        change_types = tuple(
            change.change_type
            for change in update.changes
        )
        self.assertIn("software-changed", change_types)
        self.assertIn("port-closed", change_types)
        self.assertIn("port-opened", change_types)


if __name__ == "__main__":
    unittest.main()
