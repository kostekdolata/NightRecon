"""CLI tests for bounded NightRecon API probing."""

import contextlib
import io
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from nightrecon.api_execution import ApiExecutionResult
from nightrecon.api_models import (
    ApiInventory,
    ApiOperation,
    ApiParameter,
)
from nightrecon.api_policy import ApiRequestState
from nightrecon.cli import main


def _inventory():
    return ApiInventory(
        specification="openapi",
        specification_version="3.1.0",
        title="Probe API",
        api_version="1",
        servers=(),
        operations=(
            ApiOperation(
                method="GET",
                path="/status",
                operation_id="status",
                summary="",
                parameters=(),
                request_content_types=(),
                response_statuses=("200",),
                security_schemes=(),
            ),
            ApiOperation(
                method="HEAD",
                path="/health",
                operation_id="health",
                summary="",
                parameters=(),
                request_content_types=(),
                response_statuses=("200",),
                security_schemes=(),
            ),
            ApiOperation(
                method="POST",
                path="/users",
                operation_id="createUser",
                summary="",
                parameters=(),
                request_content_types=("application/json",),
                response_statuses=("201",),
                security_schemes=(),
            ),
            ApiOperation(
                method="GET",
                path="/users/{id}",
                operation_id="getUser",
                summary="",
                parameters=(
                    ApiParameter(
                        name="id",
                        location="path",
                        required=True,
                        schema_type="string",
                    ),
                ),
                request_content_types=(),
                response_statuses=("200",),
                security_schemes=(),
            ),
        ),
        security_scheme_names=(),
    )


class CliApiProbeTests(unittest.TestCase):
    def run_cli(self, *args):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch.object(
            sys,
            "argv",
            ["nightrecon", *args],
        ):
            with contextlib.redirect_stdout(stdout):
                with contextlib.redirect_stderr(stderr):
                    try:
                        main()
                        code = 0
                    except SystemExit as exc:
                        code = exc.code

        return code, stdout.getvalue(), stderr.getvalue()

    def test_explicit_safe_operation_executes_with_ephemeral_auth(self):
        secret = "Bearer api-cli-secret"
        result = ApiExecutionResult(
            success=True,
            reason="completed",
            url="https://example.test/api/status",
            method="GET",
            operation_id="status",
            status=200,
            content_type="application/json",
            byte_count=16,
            state=ApiRequestState(
                requests_used=1,
                max_requests=2,
            ),
        )

        with patch.dict(
            os.environ,
            {
                "NIGHTRECON_API_AUTH": secret,
            },
            clear=False,
        ):
            with patch(
                "nightrecon.cli.load_api_description",
                return_value=_inventory(),
            ):
                with patch(
                    "nightrecon.cli.execute_api_request",
                    return_value=result,
                ) as execute:
                    with patch(
                        "nightrecon.cli.ResultStore"
                    ) as store_class:
                        store_class.return_value.save_api_inventory_report.return_value = (
                            Path("results/session-api.json")
                        )
                        store_class.return_value.save_api_validation_report.return_value = (
                            Path("results/session-api-validation.json")
                        )

                        with patch(
                            "nightrecon.cli.NightReconLogger"
                        ):
                            code, stdout, stderr = self.run_cli(
                                "api",
                                "probe",
                                "openapi.json",
                                "--base-url",
                                "https://example.test/api",
                                "--scope",
                                "example.test",
                                "--operation",
                                "status",
                                "--max-requests",
                                "2",
                                "--authorization-env",
                                "NIGHTRECON_API_AUTH",
                            )

        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertIn(
            "API Validation Summary: selected=1 attempted=1 successful=1 failed=0",
            stdout,
        )
        self.assertIn(
            "API PROBE GET https://example.test/api/status",
            stdout,
        )
        self.assertNotIn(
            "api-cli-secret",
            stdout,
        )
        self.assertEqual(
            execute.call_count,
            1,
        )
        kwargs = execute.call_args.kwargs
        self.assertEqual(
            kwargs["authorization"],
            secret,
        )
        self.assertEqual(
            kwargs["request"].url,
            "https://example.test/api/status",
        )
        self.assertTrue(
            kwargs["authorized"]
        )
        (
            store_class.return_value
            .save_api_inventory_report
            .assert_called_once()
        )
        (
            store_class.return_value
            .save_api_validation_report
            .assert_called_once()
        )
        saved = (
            store_class.return_value
            .save_api_validation_report
            .call_args.args[0]
        )
        self.assertNotIn(
            "api-cli-secret",
            repr(saved),
        )

    def test_mutating_operation_is_rejected_before_executor(self):
        with patch(
            "nightrecon.cli.load_api_description",
            return_value=_inventory(),
        ):
            with patch(
                "nightrecon.cli.execute_api_request"
            ) as execute:
                code, stdout, stderr = self.run_cli(
                    "api",
                    "probe",
                    "openapi.json",
                    "--base-url",
                    "https://example.test/api",
                    "--scope",
                    "example.test",
                    "--operation",
                    "createUser",
                )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn(
            "blocked method POST",
            stderr,
        )
        execute.assert_not_called()

    def test_required_parameter_operation_is_rejected_before_executor(self):
        with patch(
            "nightrecon.cli.load_api_description",
            return_value=_inventory(),
        ):
            with patch(
                "nightrecon.cli.execute_api_request"
            ) as execute:
                code, stdout, stderr = self.run_cli(
                    "api",
                    "probe",
                    "openapi.json",
                    "--base-url",
                    "https://example.test/api",
                    "--scope",
                    "example.test",
                    "--operation",
                    "getUser",
                )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn(
            "requires parameter values",
            stderr,
        )
        execute.assert_not_called()

    def test_selected_operations_must_fit_budget_before_first_request(self):
        with patch(
            "nightrecon.cli.load_api_description",
            return_value=_inventory(),
        ):
            with patch(
                "nightrecon.cli.execute_api_request"
            ) as execute:
                code, stdout, stderr = self.run_cli(
                    "api",
                    "probe",
                    "openapi.json",
                    "--base-url",
                    "https://example.test/api",
                    "--scope",
                    "example.test",
                    "--operation",
                    "status",
                    "--operation",
                    "health",
                    "--max-requests",
                    "1",
                )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn(
            "exceed max_requests",
            stderr,
        )
        execute.assert_not_called()

    def test_out_of_scope_probe_is_rejected_before_executor(self):
        with patch(
            "nightrecon.cli.load_api_description",
            return_value=_inventory(),
        ):
            with patch(
                "nightrecon.cli.execute_api_request"
            ) as execute:
                with patch(
                    "nightrecon.cli.NightReconLogger"
                ):
                    code, stdout, stderr = self.run_cli(
                        "api",
                        "probe",
                        "openapi.json",
                        "--base-url",
                        "https://example.test/api",
                        "--scope",
                        "other.test",
                        "--operation",
                        "status",
                    )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn(
            "outside the authorized scope",
            stderr,
        )
        execute.assert_not_called()

    def test_missing_authorization_environment_variable_fails_before_request(self):
        with patch.dict(
            os.environ,
            {},
            clear=True,
        ):
            with patch(
                "nightrecon.cli.load_api_description",
                return_value=_inventory(),
            ):
                with patch(
                    "nightrecon.cli.execute_api_request"
                ) as execute:
                    code, stdout, stderr = self.run_cli(
                        "api",
                        "probe",
                        "openapi.json",
                        "--base-url",
                        "https://example.test/api",
                        "--scope",
                        "example.test",
                        "--operation",
                        "status",
                        "--authorization-env",
                        "MISSING_API_AUTH",
                    )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn(
            "MISSING_API_AUTH",
            stderr,
        )
        execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
