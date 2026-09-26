"""CLI tests for NightRecon passive API inspection."""

import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from nightrecon.api_models import (
    ApiInventory,
    ApiOperation,
    ApiParameter,
    ApiServer,
)
from nightrecon.api_openapi import (
    ApiDescriptionRuntimeUnavailable,
)
from nightrecon.cli import main


def _inventory():
    return ApiInventory(
        specification="openapi",
        specification_version="3.1.0",
        title="Example API",
        api_version="1",
        servers=(
            ApiServer(
                url="https://example.test/api"
            ),
            ApiServer(
                url="https://outside.test/api"
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


class CliApiInspectTests(unittest.TestCase):
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

    def test_passive_inspection_saves_redacted_inventory(self):
        with patch(
            "nightrecon.cli.load_api_description",
            return_value=_inventory(),
        ) as loader:
            with patch(
                "nightrecon.cli.ResultStore"
            ) as store_class:
                store_class.return_value.save_api_inventory_report.return_value = (
                    Path("results/session-api.json")
                )

                with patch(
                    "nightrecon.cli.NightReconLogger"
                ):
                    code, stdout, stderr = self.run_cli(
                        "api",
                        "inspect",
                        "openapi.json",
                        "--base-url",
                        "https://example.test/api",
                        "--scope",
                        "example.test",
                    )

        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertIn(
            "API Description: openapi 3.1.0",
            stdout,
        )
        self.assertIn(
            "operations=2 safe=1 mutating=1",
            stdout,
        )
        self.assertIn(
            "API SERVER https://example.test/api same_origin=yes",
            stdout,
        )
        self.assertIn(
            "API SERVER https://outside.test/api same_origin=no",
            stdout,
        )
        self.assertIn(
            "API OPERATION GET /users id=listUsers",
            stdout,
        )
        self.assertIn(
            "API EXTERNAL REF https://schemas.example.test/user.yaml",
            stdout,
        )
        self.assertNotIn(
            "Authorization",
            stdout,
        )
        loader.assert_called_once_with(
            "openapi.json",
            max_bytes=2_097_152,
        )

        report = (
            store_class.return_value
            .save_api_inventory_report
            .call_args.args[0]
        )
        self.assertEqual(
            report.base_origin,
            "https://example.test",
        )
        self.assertEqual(
            len(report.operations),
            2,
        )

    def test_out_of_scope_base_is_rejected_before_persistence(self):
        with patch(
            "nightrecon.cli.load_api_description",
            return_value=_inventory(),
        ):
            with patch(
                "nightrecon.cli.ResultStore"
            ) as store_class:
                with patch(
                    "nightrecon.cli.NightReconLogger"
                ):
                    code, stdout, stderr = self.run_cli(
                        "api",
                        "inspect",
                        "openapi.json",
                        "--base-url",
                        "https://example.test",
                        "--scope",
                        "other.test",
                    )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn(
            "outside the authorized scope",
            stderr,
        )
        (
            store_class.return_value
            .save_api_inventory_report
            .assert_not_called()
        )

    def test_base_url_credentials_are_rejected_before_loading_spec(self):
        with patch(
            "nightrecon.cli.load_api_description"
        ) as loader:
            code, stdout, stderr = self.run_cli(
                "api",
                "inspect",
                "openapi.json",
                "--base-url",
                "https://user:secret@example.test/api",
                "--scope",
                "example.test",
            )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn(
            "must not contain URL credentials",
            stderr,
        )
        self.assertNotIn(
            "user:secret",
            stderr,
        )
        loader.assert_not_called()

    def test_base_url_query_is_rejected_before_loading_spec(self):
        with patch(
            "nightrecon.cli.load_api_description"
        ) as loader:
            code, stdout, stderr = self.run_cli(
                "api",
                "inspect",
                "openapi.json",
                "--base-url",
                "https://example.test/api?token=secret",
                "--scope",
                "example.test",
            )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn(
            "must not contain a query string or fragment",
            stderr,
        )
        self.assertNotIn(
            "token=secret",
            stderr,
        )
        loader.assert_not_called()

    def test_yaml_runtime_unavailable_is_reported_without_traceback(self):
        with patch(
            "nightrecon.cli.load_api_description",
            side_effect=ApiDescriptionRuntimeUnavailable(
                "YAML API descriptions require the NightRecon api extra."
            ),
        ):
            code, stdout, stderr = self.run_cli(
                "api",
                "inspect",
                "openapi.yaml",
                "--base-url",
                "https://example.test",
                "--scope",
                "example.test",
            )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn(
            "require the NightRecon api extra",
            stderr,
        )

    def test_invalid_spec_limit_is_rejected_before_loading(self):
        with patch(
            "nightrecon.cli.load_api_description"
        ) as loader:
            code, stdout, stderr = self.run_cli(
                "api",
                "inspect",
                "openapi.json",
                "--base-url",
                "https://example.test",
                "--scope",
                "example.test",
                "--max-spec-bytes",
                "0",
            )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn(
            "max_spec_bytes must be at least 1",
            stderr,
        )
        loader.assert_not_called()


if __name__ == "__main__":
    unittest.main()
