"""CLI integration tests for NightRecon assessment checks."""

import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from nightrecon.assessment_engine import (
    AssessmentCheckMetadata,
    AssessmentExecutionResult,
    AssessmentFinding,
    CheckIntrusiveness,
    ServiceAssessmentResult,
)
from nightrecon.check_catalog import CheckCatalogResult
from nightrecon.cli import main
from nightrecon.service_detection import ServiceDetectionResult
from nightrecon.tcp_scanner import TcpPortResult


class _Check:
    def __init__(
        self,
        check_id="web.example",
        intrusiveness=CheckIntrusiveness.PASSIVE,
    ):
        self.metadata = AssessmentCheckMetadata(
            check_id=check_id,
            name="Example",
            family="web",
            description="Example check.",
            intrusiveness=intrusiveness,
            supported_services=("http",),
            tags=("http", "example"),
        )

    def run(self, context):
        return ()


class CliAssessmentTests(unittest.TestCase):
    def _scan_results(self):
        return (
            TcpPortResult(
                address="127.0.0.1",
                port=80,
                is_open=True,
                error_code=0,
            ),
        )

    def _service_results(self):
        return (
            ServiceDetectionResult(
                address="127.0.0.1",
                port=80,
                service="http",
                banner="",
            ),
        )

    def test_assessment_is_disabled_by_default(self):
        with patch.object(
            sys,
            "argv",
            [
                "nightrecon",
                "scan",
                "127.0.0.1",
                "--scope",
                "127.0.0.1",
                "--ports",
                "80",
            ],
        ):
            with patch(
                "nightrecon.cli.scan_tcp_ports",
                return_value=self._scan_results(),
            ):
                with patch(
                    "nightrecon.cli.detect_services",
                    return_value=self._service_results(),
                ):
                    with patch(
                        "nightrecon.cli.load_check_catalog"
                    ) as load_catalog:
                        with patch(
                            "nightrecon.cli.assess_services"
                        ) as assess:
                            with patch(
                                "nightrecon.cli.ResultStore"
                            ) as store_class:
                                store_class.return_value.save_report.return_value = (
                                    Path("results/test.json")
                                )

                                with patch(
                                    "nightrecon.cli.NightReconLogger"
                                ):
                                    with contextlib.redirect_stdout(
                                        io.StringIO()
                                    ):
                                        main()

        load_catalog.assert_not_called()
        assess.assert_not_called()

        report = store_class.return_value.save_report.call_args.args[0]
        self.assertFalse(report.assessment_enabled)
        self.assertEqual(report.assessments, ())

    def test_assessment_filters_and_executes_selected_checks(self):
        selected_check = _Check()
        catalog = CheckCatalogResult(
            checks=(
                selected_check,
                _Check("tls.other"),
            ),
            errors=("plugin.warning: unavailable",),
        )
        finding = AssessmentFinding(
            check_id="web.example",
            title="Example finding",
            summary="Example summary.",
            evidence=("example=true",),
        )
        assessment_results = (
            ServiceAssessmentResult(
                address="127.0.0.1",
                port=80,
                service="http",
                executions=(
                    AssessmentExecutionResult(
                        check_id="web.example",
                        status="completed",
                        findings=(finding,),
                    ),
                ),
            ),
        )

        stdout = io.StringIO()

        with patch.object(
            sys,
            "argv",
            [
                "nightrecon",
                "scan",
                "127.0.0.1",
                "--scope",
                "127.0.0.1",
                "--ports",
                "80",
                "--assessment",
                "--check",
                "web.example",
                "--max-check-intrusiveness",
                "passive",
            ],
        ):
            with patch(
                "nightrecon.cli.scan_tcp_ports",
                return_value=self._scan_results(),
            ):
                with patch(
                    "nightrecon.cli.detect_services",
                    return_value=self._service_results(),
                ):
                    with patch(
                        "nightrecon.cli.load_check_catalog",
                        return_value=catalog,
                    ):
                        with patch(
                            "nightrecon.cli.assess_services",
                            return_value=assessment_results,
                        ) as assess:
                            with patch(
                                "nightrecon.cli.ResultStore"
                            ) as store_class:
                                store_class.return_value.save_report.return_value = (
                                    Path("results/test.json")
                                )

                                with patch(
                                    "nightrecon.cli.NightReconLogger"
                                ):
                                    with contextlib.redirect_stdout(stdout):
                                        main()

        assess.assert_called_once_with(
            target="127.0.0.1",
            services=self._service_results(),
            checks=(selected_check,),
            max_intrusiveness=CheckIntrusiveness.PASSIVE,
            authorized=True,
        )

        report = store_class.return_value.save_report.call_args.args[0]
        self.assertTrue(report.assessment_enabled)
        self.assertEqual(
            report.assessments,
            assessment_results,
        )
        self.assertEqual(
            report.assessment_catalog_errors,
            ("plugin.warning: unavailable",),
        )

        output = stdout.getvalue()
        self.assertIn(
            "ASSESSMENT 127.0.0.1:80 http",
            output,
        )
        self.assertIn(
            "CHECK web.example status=completed",
            output,
        )
        self.assertIn(
            "FINDING web.example severity=unspecified",
            output,
        )

    def test_destructive_intrusiveness_is_not_available_from_scan_cli(self):
        stderr = io.StringIO()

        with patch.object(
            sys,
            "argv",
            [
                "nightrecon",
                "scan",
                "127.0.0.1",
                "--scope",
                "127.0.0.1",
                "--assessment",
                "--max-check-intrusiveness",
                "destructive",
            ],
        ):
            with contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as exc:
                    main()

        self.assertEqual(exc.exception.code, 2)
        self.assertIn(
            "invalid choice: 'destructive'",
            stderr.getvalue(),
        )

    def test_check_filter_requires_assessment(self):
        stderr = io.StringIO()

        with patch.object(
            sys,
            "argv",
            [
                "nightrecon",
                "scan",
                "127.0.0.1",
                "--scope",
                "127.0.0.1",
                "--check",
                "web.example",
            ],
        ):
            with contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as exc:
                    main()

        self.assertEqual(exc.exception.code, 2)
        self.assertIn(
            "--check/--check-family/--check-tag require --assessment",
            stderr.getvalue(),
        )


if __name__ == "__main__":
    unittest.main()
