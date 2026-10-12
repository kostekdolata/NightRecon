"""Regression coverage for Windows deletion of closed SQLite stores."""
import tempfile
import unittest
from pathlib import Path

from nightrecon_red_engine.atomic_action_ledger import AtomicActionLedger
from nightrecon_red_engine.finding_review_store import FindingStore, FindingRecord


class TestSQLiteCleanup(unittest.TestCase):
    def test_action_ledger_closes_connections_after_operations(self):
        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "actions.db"
            ledger = AtomicActionLedger(database)
            ledger.provision("lab", limit=2)
            ledger.reserve("lab", "one")
            ledger.revoke("lab")
            database.unlink()
            self.assertFalse(database.exists())

    def test_review_store_closes_connections_after_operations(self):
        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "review.db"
            store = FindingStore(database)
            store.upsert(FindingRecord("lab", "asset", "rule", "open", "evidence", "note"))
            self.assertEqual(len(store.list_findings("lab")), 1)
            store.retest("lab", "asset", "rule", "retest", False)
            database.unlink()
            self.assertFalse(database.exists())
