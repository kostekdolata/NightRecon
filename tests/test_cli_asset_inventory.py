"""CLI tests for NightRecon persistent asset inventory."""

import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from nightrecon.asset_inventory import (
    AssetChange,
    AssetChangeEvent,
    AssetInventory,
    AssetInventoryUpdate,
    AssetRecord,
    AssetServiceRecord,
)
from nightrecon.cli import main
from nightrecon.host_discovery import HostDiscoveryResult
from nightrecon.service_detection import ServiceDetectionResult
from nightrecon.tcp_scanner import TcpPortResult


class CliAssetInventoryTests(unittest.TestCase):
    def test_discovery_can_update_asset_inventory(self):
        results = (
            HostDiscoveryResult(
                address="192.0.2.2",
                responsive=True,
                method="tcp-connect",
                port=443,
                observation="tcp-open",
                hostname="host2.example.test",
            ),
        )
        updated = AssetInventory(
            assets=(
                AssetRecord(
                    address="192.0.2.2",
                    first_seen="2026-09-24T10:00:00+00:00",
                    last_seen="2026-09-24T10:00:00+00:00",
                    last_checked_at="2026-09-24T10:00:00+00:00",
                ),
            ),
            updated_at="2026-09-24T10:00:00+00:00",
        )
        update = AssetInventoryUpdate(
            inventory=updated,
            changes=(
                AssetChange(
                    address="192.0.2.2",
                    change_type="new-asset",
                ),
            ),
        )
        stdout = io.StringIO()

        with patch.object(
            sys,
            "argv",
            [
                "nightrecon",
                "discover",
                "192.0.2.0/30",
                "--scope",
                "192.0.2.0/24",
                "--update-inventory",
                "--inventory-dir",
                "assets-test",
            ],
        ):
            with patch(
                "nightrecon.cli.discover_hosts",
                return_value=results,
            ):
                with patch(
                    "nightrecon.cli.ResultStore"
                ) as result_store:
                    result_store.return_value.save_discovery_report.return_value = (
                        Path("results/discovery.json")
                    )

                    with patch(
                        "nightrecon.cli.AssetInventoryStore"
                    ) as inventory_store_class:
                        inventory_store = (
                            inventory_store_class.return_value
                        )
                        inventory_store.load.return_value = (
                            AssetInventory.empty()
                        )
                        inventory_store.save.return_value = (
                            Path("assets-test/assets.json")
                        )

                        with patch(
                            "nightrecon.cli.apply_discovery_report",
                            return_value=update,
                        ) as apply_update:
                            with patch(
                                "nightrecon.cli.NightReconLogger"
                            ):
                                with contextlib.redirect_stdout(stdout):
                                    main()

        inventory_store_class.assert_called_once_with(
            "assets-test"
        )
        apply_update.assert_called_once()
        inventory_store.save.assert_called_once_with(
            updated
        )
        inventory_store.append_change_events.assert_called_once()
        discovery_events = (
            inventory_store.append_change_events
            .call_args.args[0]
        )
        self.assertEqual(
            discovery_events[0].source_type,
            "discovery",
        )
        self.assertEqual(
            discovery_events[0].change.change_type,
            "new-asset",
        )
        self.assertIn(
            "Inventory changes: 1",
            stdout.getvalue(),
        )
        self.assertIn(
            "ASSET CHANGE 192.0.2.2 new-asset",
            stdout.getvalue(),
        )

    def test_scan_can_update_asset_inventory(self):
        scan_results = (
            TcpPortResult(
                address="192.0.2.10",
                port=80,
                is_open=True,
                error_code=0,
            ),
        )
        services = (
            ServiceDetectionResult(
                address="192.0.2.10",
                port=80,
                service="http",
                banner="",
            ),
        )
        updated = AssetInventory(
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
                        ),
                    ),
                ),
            ),
            updated_at="2026-09-24T10:00:00+00:00",
        )
        update = AssetInventoryUpdate(
            inventory=updated,
            changes=(
                AssetChange(
                    address="192.0.2.10",
                    change_type="port-opened",
                    port=80,
                    after="http",
                ),
            ),
        )
        stdout = io.StringIO()

        with patch.object(
            sys,
            "argv",
            [
                "nightrecon",
                "scan",
                "192.0.2.10",
                "--scope",
                "192.0.2.0/24",
                "--ports",
                "80",
                "--update-inventory",
                "--inventory-dir",
                "assets-test",
            ],
        ):
            with patch(
                "nightrecon.cli.scan_tcp_ports",
                return_value=scan_results,
            ):
                with patch(
                    "nightrecon.cli.detect_services",
                    return_value=services,
                ):
                    with patch(
                        "nightrecon.cli.ResultStore"
                    ) as result_store:
                        result_store.return_value.save_report.return_value = (
                            Path("results/scan.json")
                        )

                        with patch(
                            "nightrecon.cli.AssetInventoryStore"
                        ) as inventory_store_class:
                            inventory_store = (
                                inventory_store_class.return_value
                            )
                            inventory_store.load.return_value = (
                                AssetInventory.empty()
                            )
                            inventory_store.save.return_value = (
                                Path("assets-test/assets.json")
                            )

                            with patch(
                                "nightrecon.cli.apply_scan_report",
                                return_value=update,
                            ) as apply_update:
                                with patch(
                                    "nightrecon.cli.NightReconLogger"
                                ):
                                    with contextlib.redirect_stdout(stdout):
                                        main()

        inventory_store_class.assert_called_once_with(
            "assets-test"
        )
        apply_update.assert_called_once()
        inventory_store.save.assert_called_once_with(
            updated
        )
        inventory_store.append_change_events.assert_called_once()
        scan_events = (
            inventory_store.append_change_events
            .call_args.args[0]
        )
        self.assertEqual(
            scan_events[0].source_type,
            "scan",
        )
        self.assertEqual(
            scan_events[0].change.port,
            80,
        )
        self.assertIn(
            "ASSET CHANGE 192.0.2.10 port-opened port=80",
            stdout.getvalue(),
        )

    def test_assets_history_is_offline_and_filterable(self):
        events = (
            AssetChangeEvent(
                observed_at="2026-09-24T10:00:00+00:00",
                session_id="session-1",
                source_type="discovery",
                change=AssetChange(
                    address="192.0.2.10",
                    change_type="new-asset",
                ),
            ),
            AssetChangeEvent(
                observed_at="2026-09-24T11:00:00+00:00",
                session_id="session-2",
                source_type="scan",
                change=AssetChange(
                    address="192.0.2.10",
                    change_type="port-opened",
                    port=443,
                    after="https",
                ),
            ),
        )
        stdout = io.StringIO()

        with patch.object(
            sys,
            "argv",
            [
                "nightrecon",
                "assets",
                "history",
                "--inventory-dir",
                "assets-test",
                "--address",
                "192.0.2.10",
                "--limit",
                "10",
            ],
        ):
            with patch(
                "nightrecon.cli.AssetInventoryStore"
            ) as store_class:
                store_class.return_value.load_change_history.return_value = (
                    events
                )

                with contextlib.redirect_stdout(stdout):
                    main()

        store_class.return_value.load_change_history.assert_called_once_with(
            address="192.0.2.10",
            limit=10,
        )
        output = stdout.getvalue()
        self.assertIn("Asset changes: 2", output)
        self.assertIn(
            "ASSET CHANGE 192.0.2.10 new-asset "
            "source=discovery session=session-1",
            output,
        )
        self.assertIn(
            "ASSET CHANGE 192.0.2.10 port-opened port=443 "
            "after=https source=scan session=session-2",
            output,
        )

    def test_assets_list_is_offline_and_displays_inventory(self):
        inventory = AssetInventory(
            assets=(
                AssetRecord(
                    address="192.0.2.10",
                    first_seen="2026-09-24T10:00:00+00:00",
                    last_seen="2026-09-24T12:00:00+00:00",
                    last_checked_at="2026-09-24T12:00:00+00:00",
                    hostnames=("web.example.test",),
                    services=(
                        AssetServiceRecord(
                            port=80,
                            service="http",
                            product="nginx",
                            version="1.24.0",
                        ),
                    ),
                ),
            ),
            updated_at="2026-09-24T12:00:00+00:00",
        )
        stdout = io.StringIO()

        with patch.object(
            sys,
            "argv",
            [
                "nightrecon",
                "assets",
                "list",
                "--inventory-dir",
                "assets-test",
            ],
        ):
            with patch(
                "nightrecon.cli.AssetInventoryStore"
            ) as store_class:
                store_class.return_value.load.return_value = (
                    inventory
                )

                with contextlib.redirect_stdout(stdout):
                    main()

        output = stdout.getvalue()
        self.assertIn(
            "Assets: 1",
            output,
        )
        self.assertIn(
            "ASSET 192.0.2.10 hostnames=web.example.test services=80/http/nginx/1.24.0",
            output,
        )


if __name__ == "__main__":
    unittest.main()
