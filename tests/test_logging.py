"""Tests for NightRecon structured logging."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from nightrecon.logging import NightReconLogger


class LoggingTests(unittest.TestCase):
    def test_log_file_is_created(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            logger = NightReconLogger(temp_dir)

            log_path = logger.write(
                "scan.created",
                target="127.0.0.1",
            )

            self.assertTrue(log_path.exists())

    def test_log_record_contains_event_data(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            logger = NightReconLogger(temp_dir)

            log_path = logger.write(
                "scan.created",
                target="127.0.0.1",
                session_id="test-session",
            )

            with log_path.open("r", encoding="utf-8") as file:
                record = json.loads(file.readline())

            self.assertEqual(record["event"], "scan.created")
            self.assertEqual(record["target"], "127.0.0.1")
            self.assertEqual(record["session_id"], "test-session")
            self.assertIn("timestamp", record)

    def test_secret_fields_and_authorization_values_are_redacted(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            logger = NightReconLogger(temp_dir)

            log_path = logger.write(
                "secret.test",
                password="never-log-this",
                authorization="Bearer abc123",
                authorization_reference="approval://keep-this",
                credential_id="cred-1",
                nested={
                    "access-token": "nested-secret",
                    "safe": "visible",
                    "header": "Basic dXNlcjpwYXNz",
                },
            )
            record = json.loads(log_path.read_text(encoding="utf-8"))

            self.assertEqual(record["password"], "<redacted>")
            self.assertEqual(record["authorization"], "<redacted>")
            self.assertEqual(record["authorization_reference"], "approval://keep-this")
            self.assertEqual(record["credential_id"], "cred-1")
            self.assertEqual(record["nested"]["access-token"], "<redacted>")
            self.assertEqual(record["nested"]["safe"], "visible")
            self.assertEqual(record["nested"]["header"], "<redacted>")
            serialized = json.dumps(record)
            self.assertNotIn("never-log-this", serialized)
            self.assertNotIn("nested-secret", serialized)
            self.assertNotIn("abc123", serialized)
            self.assertNotIn("dXNlcjpwYXNz", serialized)

    def test_log_file_is_private_on_posix(self):
        if os.name == "nt":
            self.skipTest("POSIX permission bits are not authoritative on Windows")
        with tempfile.TemporaryDirectory() as temp_dir:
            logger = NightReconLogger(temp_dir)
            log_path = logger.write("permission.test")

            self.assertEqual(log_path.stat().st_mode & 0o777, 0o600)

    def test_non_json_object_is_rejected_without_repr_serialization(self):
        class SecretLike:
            def __repr__(self):
                return "must-not-appear"

        with tempfile.TemporaryDirectory() as temp_dir:
            logger = NightReconLogger(temp_dir)
            with self.assertRaises(TypeError):
                logger.write("object.test", payload=SecretLike())

            log_path = Path(temp_dir) / "nightrecon.jsonl"
            self.assertFalse(log_path.exists())

    def test_multiple_records_are_appended(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            logger = NightReconLogger(temp_dir)

            logger.write("first.event")
            logger.write("second.event")

            log_path = Path(temp_dir) / "nightrecon.jsonl"

            with log_path.open("r", encoding="utf-8") as file:
                records = [
                    json.loads(line)
                    for line in file
                    if line.strip()
                ]

            self.assertEqual(len(records), 2)
            self.assertEqual(records[0]["event"], "first.event")
            self.assertEqual(records[1]["event"], "second.event")


if __name__ == "__main__":
    unittest.main()
