"""Operations snapshot must remain read-only and engagement-scoped."""
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages" / "red-night"))
from red_night_app.operations_read_model import read_operations_snapshot


class TestOperationsReadModel(unittest.TestCase):
    def test_missing_authority_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = read_operations_snapshot(
                engagement_id="lab", authority_db=root / "authority.db",
                audit_path=root / "audit.jsonl", review_db=root / "review.db")
            self.assertEqual(result.status, "UNAVAILABLE")
            self.assertFalse((root / "authority.db").exists())

    def test_snapshot_filters_engagement_events_and_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            authority = root / "authority.db"
            with sqlite3.connect(authority) as db:
                db.execute("CREATE TABLE engagement_authority (engagement_id TEXT, policy_json TEXT, engagement_status TEXT, actions_used INTEGER)")
                db.execute("INSERT INTO engagement_authority VALUES (?,?,?,?)",
                           ("lab", json.dumps({"max_actions": 3}), "active", 1))
            review = root / "review.db"
            with sqlite3.connect(review) as db:
                db.execute("CREATE TABLE review_findings (engagement TEXT, asset TEXT, rule_id TEXT, status TEXT, evidence_ref TEXT)")
                db.execute("INSERT INTO review_findings VALUES (?,?,?,?,?)",
                           ("lab", "127.0.0.1", "rule1", "open", "ev-1"))
            audit = root / "audit.jsonl"
            audit.write_text("\n".join(json.dumps(obj) for obj in (
                {"engagement_id": "lab", "command": "nmap", "status": "completed"},
                {"engagement_id": "other", "command": "private", "status": "failed"},
            )))
            result = read_operations_snapshot(
                engagement_id="lab", authority_db=authority,
                audit_path=audit, review_db=review)
            self.assertEqual(result.status, "ACTIVE")
            self.assertEqual(result.remaining_actions, 2)
            self.assertEqual(len(result.events), 1)
            self.assertNotIn("private", result.describe())
            self.assertEqual(len(result.findings), 1)
