"""Tests for separate API validation persistence."""

import json
import tempfile
import unittest

from nightrecon.api_validation_report import ApiValidationReport
from nightrecon.session import ScanSession
from nightrecon.storage import ResultStore
from nightrecon.targets import parse_target


class ApiValidationStorageTests(unittest.TestCase):
    def test_validation_report_is_saved_separately(self):
        session = ScanSession.create(
            target=parse_target("example.test"),
            scope_rules=("example.test",),
        )
        report = ApiValidationReport.create(
            session=session,
            base_origin="https://example.test",
            max_requests=3,
            max_response_bytes=1024,
            records=(),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ResultStore(temp_dir)
            validation_path = store.save_api_validation_report(
                report
            )

            self.assertEqual(
                validation_path.name,
                f"{session.session_id}-api-validation.json",
            )

            with validation_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                data = json.load(file)

        self.assertEqual(
            data["session_id"],
            session.session_id,
        )
        self.assertEqual(
            data["summary"]["attempted_requests"],
            0,
        )


if __name__ == "__main__":
    unittest.main()
