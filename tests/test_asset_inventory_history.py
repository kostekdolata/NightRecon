"""Tests for NightRecon asset inventory change history."""

import tempfile
import unittest

from nightrecon.asset_inventory import (
    AssetChange,
    AssetChangeEvent,
)
from nightrecon.asset_inventory_store import AssetInventoryStore


class AssetInventoryHistoryTests(unittest.TestCase):
    def test_change_history_round_trip_and_filtering(self):
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
            AssetChangeEvent(
                observed_at="2026-09-24T12:00:00+00:00",
                session_id="session-3",
                source_type="scan",
                change=AssetChange(
                    address="192.0.2.20",
                    change_type="new-asset",
                ),
            ),
        )

        with tempfile.TemporaryDirectory() as directory:
            store = AssetInventoryStore(directory)
            path = store.append_change_events(events)

            self.assertEqual(
                path.name,
                "changes.jsonl",
            )
            self.assertEqual(
                store.load_change_history(),
                events,
            )
            self.assertEqual(
                store.load_change_history(
                    address="192.0.2.10",
                ),
                events[:2],
            )
            self.assertEqual(
                store.load_change_history(
                    limit=1,
                ),
                events[-1:],
            )

    def test_empty_change_append_does_not_create_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AssetInventoryStore(directory)

            self.assertIsNone(
                store.append_change_events(())
            )
            self.assertEqual(
                store.load_change_history(),
                (),
            )

    def test_invalid_history_record_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AssetInventoryStore(directory)
            store.root.mkdir(
                parents=True,
                exist_ok=True,
            )
            store.history_path.write_text(
                '{"bad": true}\n',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                ValueError,
                "Invalid asset change history",
            ):
                store.load_change_history()


if __name__ == "__main__":
    unittest.main()
