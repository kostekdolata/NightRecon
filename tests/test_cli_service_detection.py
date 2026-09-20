"""CLI integration tests for NightRecon service detection."""

import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from nightrecon.cli import main
from nightrecon.service_detection import ServiceDetectionResult
from nightrecon.tcp_scanner import TcpPortResult


class CliServiceDetectionTests(unittest.TestCase):
    def test_service_detection_runs_only_for_open_ports(self):
        scan_results = (
            TcpPortResult(
                address="127.0.0.1",
                port=80,
                is_open=True,
                error_code=0,
            ),
            TcpPortResult(
                address="127.0.0.1",
                port=443,
                is_open=False,
                error_code=10061,
            ),
        )

        service_result = ServiceDetectionResult(
            address="127.0.0.1",
            port=80,
            service="http",
            banner="",
        )

        stdout = io.StringIO()
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
                "--ports",
                "80,443",
            ],
        ):
            with patch(
                "nightrecon.cli.scan_tcp_ports",
                return_value=scan_results,
            ):
                with patch(
                    "nightrecon.cli.detect_service",
                    return_value=service_result,
                ) as detector:
                    with patch(
                        "nightrecon.cli.ResultStore"
                    ) as store_class:
                        store_class.return_value.save_report.return_value = (
                            Path("results/test.json")
                        )

                        with patch("nightrecon.cli.NightReconLogger"):
                            with contextlib.redirect_stdout(stdout):
                                with contextlib.redirect_stderr(stderr):
                                    try:
                                        main()
                                        exit_code = 0
                                    except SystemExit as exc:
                                        exit_code = exc.code

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr.getvalue(), "")

        detector.assert_called_once_with(
            address="127.0.0.1",
            port=80,
            timeout=2.0,
        )

        report = store_class.return_value.save_report.call_args.args[0]

        self.assertEqual(len(report.services), 1)
        self.assertEqual(report.services[0].port, 80)
        self.assertEqual(report.services[0].service, "http")


if __name__ == "__main__":
    unittest.main()