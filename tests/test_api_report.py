"""Tests for NightRecon API inventory reporting."""

import unittest

from nightrecon.api_models import (
    ApiInventory,
    ApiOperation,
    ApiParameter,
    ApiServer,
)
from nightrecon.api_report import ApiInventoryReport
from nightrecon.session import ScanSession
from nightrecon.targets import parse_target


class ApiReportTests(unittest.TestCase):
    def test_report_is_structured_and_non_secret(self):
        session = ScanSession.create(
            target=parse_target("example.test"),
            scope_rules=("example.test",),
        )
        inventory = ApiInventory(
            specification="openapi",
            specification_version="3.1.0",
            title="Example API",
            api_version="1",
            servers=(
                ApiServer(
                    url="https://example.test/api"
                ),
            ),
            operations=(
                ApiOperation(
                    method="GET",
                    path="/users",
                    operation_id="listUsers",
                    summary="List users",
                    parameters=(
                        ApiParameter(
                            name="limit",
                            location="query",
                            required=False,
                            schema_type="integer",
                            schema_format="int32",
                        ),
                    ),
                    request_content_types=(),
                    response_statuses=("200",),
                    security_schemes=("bearerAuth",),
                ),
                ApiOperation(
                    method="POST",
                    path="/users",
                    operation_id="createUser",
                    summary="Create user",
                    parameters=(),
                    request_content_types=(
                        "application/json",
                    ),
                    response_statuses=("201",),
                    security_schemes=("bearerAuth",),
                ),
            ),
            security_scheme_names=(
                "bearerAuth",
            ),
            external_references_observed=(
                "https://schemas.example.test/user.yaml",
            ),
        )

        report = ApiInventoryReport.create(
            session=session,
            base_origin="https://example.test",
            inventory=inventory,
        )
        data = report.to_dict()

        self.assertEqual(
            data["summary"]["operations"],
            2,
        )
        self.assertEqual(
            data["summary"]["safe_operations"],
            1,
        )
        self.assertEqual(
            data["summary"]["mutating_operations"],
            1,
        )
        self.assertEqual(
            data["operations"][0]["parameters"][0]["name"],
            "limit",
        )
        self.assertEqual(
            data["security_scheme_names"],
            ("bearerAuth",),
        )
        serialized = repr(data)
        self.assertNotIn(
            "Authorization",
            serialized,
        )
        self.assertNotIn(
            "CookieJar",
            serialized,
        )
        self.assertNotIn(
            "secret=",
            serialized,
        )


if __name__ == "__main__":
    unittest.main()
