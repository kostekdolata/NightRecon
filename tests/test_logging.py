"""Tests for NightRecon structured logging."""

import json
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
