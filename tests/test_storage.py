"""Tests for NightRecon result storage."""

import json
import tempfile
import unittest
from pathlib import Path

from nightrecon.session import ScanSession
from nightrecon.storage import ResultStore
from nightrecon.targets import parse_target


class ResultStoreTests(unittest.TestCase):
    def test_session_is_saved_as_json(self):
        target = parse_target("127.0.0.1")
        session = ScanSession.create(
            target=target,
            scope_rules=("127.0.0.1",),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ResultStore(temp_dir)

            output_path = store.save_session(session)

            self.assertTrue(output_path.exists())
            self.assertEqual(
                output_path.name,
                f"{session.session_id}.json",
            )

    def test_saved_json_contains_session_data(self):
        target = parse_target("example.com")
        session = ScanSession.create(
            target=target,
            scope_rules=("example.com",),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ResultStore(temp_dir)

            output_path = store.save_session(session)

            with output_path.open("r", encoding="utf-8") as file:
                data = json.load(file)

            self.assertEqual(data["session_id"], session.session_id)
            self.assertEqual(data["target"], "example.com")
            self.assertEqual(data["target_type"], "hostname")
            self.assertEqual(data["scope"], ["example.com"])
            self.assertEqual(data["status"], "created")

    def test_results_directory_is_created_automatically(self):
        target = parse_target("10.0.0.1")
        session = ScanSession.create(
            target=target,
            scope_rules=("10.0.0.0/8",),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            result_dir = Path(temp_dir) / "nested" / "results"
            store = ResultStore(result_dir)

            output_path = store.save_session(session)

            self.assertTrue(result_dir.exists())
            self.assertTrue(output_path.exists())


if __name__ == "__main__":
    unittest.main()
