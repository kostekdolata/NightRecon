"""Tests for separate NightRecon API inventory persistence."""

import json
import tempfile
import unittest

from nightrecon.api_models import ApiInventory
from nightrecon.api_report import ApiInventoryReport
from nightrecon.session import ScanSession
from nightrecon.storage import ResultStore
from nightrecon.targets import parse_target


class ApiStorageTests(unittest.TestCase):
    def test_api_report_is_saved_separately(self):
        session = ScanSession.create(
            target=parse_target("example.test"),
            scope_rules=("example.test",),
        )
        report = ApiInventoryReport.create(
            session=session,
            base_origin="https://example.test",
            inventory=ApiInventory(
                specification="openapi",
                specification_version="3.1.0",
                title="API",
                api_version="1",
                servers=(),
                operations=(),
                security_scheme_names=(),
            ),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ResultStore(temp_dir)
            session_path = store.save_session(
                session
            )
            api_path = store.save_api_inventory_report(
                report
            )

            self.assertTrue(
                session_path.exists()
            )
            self.assertTrue(
                api_path.exists()
            )
            self.assertNotEqual(
                session_path,
                api_path,
            )
            self.assertEqual(
                api_path.name,
                f"{session.session_id}-api.json",
            )

            with api_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                data = json.load(file)

        self.assertEqual(
            data["session_id"],
            session.session_id,
        )
        self.assertEqual(
            data["summary"]["operations"],
            0,
        )


if __name__ == "__main__":
    unittest.main()
