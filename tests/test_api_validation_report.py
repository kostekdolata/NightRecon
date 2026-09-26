"""Tests for NightRecon API validation reporting."""

import unittest

from nightrecon.api_execution import ApiExecutionResult
from nightrecon.api_models import ApiOperation
from nightrecon.api_planner import ApiOperationSelection
from nightrecon.api_policy import ApiRequestState
from nightrecon.api_validation_report import (
    ApiValidationRecord,
    ApiValidationReport,
)
from nightrecon.session import ScanSession
from nightrecon.targets import parse_target


class ApiValidationReportTests(unittest.TestCase):
    def test_validation_report_summarizes_non_secret_results(self):
        session = ScanSession.create(
            target=parse_target("example.test"),
            scope_rules=("example.test",),
        )
        operation = ApiOperation(
            method="GET",
            path="/status",
            operation_id="status",
            summary="",
            parameters=(),
            request_content_types=(),
            response_statuses=("200",),
            security_schemes=(),
        )
        selection = ApiOperationSelection(
            selector="status",
            operation=operation,
            url="https://example.test/api/status",
        )
        result = ApiExecutionResult(
            success=True,
            reason="completed",
            url=selection.url,
            method="GET",
            operation_id="status",
            status=200,
            content_type="application/json",
            byte_count=12,
            state=ApiRequestState(
                requests_used=1,
                max_requests=3,
            ),
        )
        record = ApiValidationRecord.from_result(
            selection=selection,
            result=result,
        )
        report = ApiValidationReport.create(
            session=session,
            base_origin="https://example.test",
            max_requests=3,
            max_response_bytes=1024,
            records=(record,),
        )
        data = report.to_dict()

        self.assertEqual(
            data["summary"]["selected_operations"],
            1,
        )
        self.assertEqual(
            data["summary"]["attempted_requests"],
            1,
        )
        self.assertEqual(
            data["summary"]["successful_requests"],
            1,
        )
        self.assertEqual(
            data["summary"]["failed_requests"],
            0,
        )
        self.assertNotIn(
            "Authorization",
            repr(data),
        )
        self.assertNotIn(
            "secret",
            repr(data),
        )


if __name__ == "__main__":
    unittest.main()
