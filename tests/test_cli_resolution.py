"""CLI integration tests for NightRecon target resolution."""

import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from nightrecon.cli import main
from nightrecon.resolver import ResolutionResult
from nightrecon.tcp_scanner import TcpPortResult


class CliResolutionTests(unittest.TestCase):

    def test_hostname_is_forwarded_for_tls_sni(self):
        resolution = ResolutionResult(
            target="example.com",
            addresses=("192.0.2.10",),
        )

        scan_results = (
            TcpPortResult(
                address="192.0.2.10",
                port=443,
                is_open=True,
                error_code=0,
            ),
        )

        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch.object(
            sys,
            "argv",
            [
                "nightrecon",
                "scan",
                "example.com",
                "--scope",
                "example.com",
                "--ports",
                "443",
            ],
        ):
            with patch(
                "nightrecon.cli.resolve_target",
                return_value=resolution,
            ):
                with patch(
                    "nightrecon.cli.scan_tcp_ports",
                    return_value=scan_results,
                ):
                    with patch(
                        "nightrecon.cli.detect_services",
                        return_value=(),
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
            address="192.0.2.10",
            ports=(443,),
            timeout=2.0,
            max_workers=50,
            server_hostname="example.com",
        )

    def run_cli(self, *args):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch("nightrecon.cli.scan_tcp_ports", return_value=()):
            with patch.object(sys, "argv", ["nightrecon", *args]):
                with contextlib.redirect_stdout(stdout):
                    with contextlib.redirect_stderr(stderr):
                        try:
                            main()
                            exit_code = 0
                        except SystemExit as exc:
                            exit_code = exc.code

        return exit_code, stdout.getvalue(), stderr.getvalue()

    def test_authorized_hostname_is_resolved(self):
        resolution = ResolutionResult(
            target="example.com",
            addresses=("192.0.2.10", "2001:db8::10"),
        )

        with patch(
            "nightrecon.cli.resolve_target",
            return_value=resolution,
        ) as resolver:
            with patch("nightrecon.cli.ResultStore") as store_class:
                store_class.return_value.save_report.return_value = Path(
                    "results/test.json"
                )

                with patch("nightrecon.cli.NightReconLogger"):
                    code, stdout, stderr = self.run_cli(
                        "scan",
                        "example.com",
                        "--scope",
                        "example.com",
                    )

        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertIn("192.0.2.10", stdout)
        self.assertIn("2001:db8::10", stdout)
        resolver.assert_called_once()

    def test_out_of_scope_target_is_never_resolved(self):
        with patch("nightrecon.cli.resolve_target") as resolver:
            with patch("nightrecon.cli.NightReconLogger"):
                code, stdout, stderr = self.run_cli(
                    "scan",
                    "api.example.com",
                    "--scope",
                    "example.com",
                )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("outside the authorized scope", stderr)
        resolver.assert_not_called()


if __name__ == "__main__":
    unittest.main()