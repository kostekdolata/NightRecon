"""Tests for the NightRecon command-line interface."""

import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from nightrecon.cli import main


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch.object(sys, "argv", ["nightrecon", *args]):
            with contextlib.redirect_stdout(stdout):
                with contextlib.redirect_stderr(stderr):
                    try:
                        main()
                        exit_code = 0
                    except SystemExit as exc:
                        exit_code = exc.code

        return exit_code, stdout.getvalue(), stderr.getvalue()

    def test_exact_ipv4_scope_is_approved(self):
        with patch("nightrecon.cli.NightReconLogger"):
            code, stdout, stderr = self.run_cli(
                "scan",
                "127.0.0.1",
                "--scope",
                "127.0.0.1",
            )

        self.assertEqual(code, 0)
        self.assertIn("Scope authorization: approved", stdout)
        self.assertEqual(stderr, "")

    def test_ipv4_inside_cidr_scope_is_approved(self):
        with patch("nightrecon.cli.NightReconLogger"):
            code, stdout, stderr = self.run_cli(
                "scan",
                "192.168.1.25",
                "--scope",
                "192.168.1.0/24",
            )

        self.assertEqual(code, 0)
        self.assertIn("Scope authorization: approved", stdout)
        self.assertEqual(stderr, "")

    def test_ipv4_outside_scope_is_rejected(self):
        with patch("nightrecon.cli.NightReconLogger"):
            code, stdout, stderr = self.run_cli(
                "scan",
                "192.168.2.25",
                "--scope",
                "192.168.1.0/24",
            )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("outside the authorized scope", stderr)

    def test_exact_hostname_scope_is_approved(self):
        with patch("nightrecon.cli.NightReconLogger"):
            code, stdout, stderr = self.run_cli(
                "scan",
                "example.com",
                "--scope",
                "example.com",
            )

        self.assertEqual(code, 0)
        self.assertIn("Scope authorization: approved", stdout)
        self.assertEqual(stderr, "")

    def test_subdomain_not_explicitly_authorized_is_rejected(self):
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

    def test_authorized_scan_saves_session(self):
        with patch("nightrecon.cli.NightReconLogger"):
            with patch("nightrecon.cli.ResultStore") as store_class:
                store = store_class.return_value
                store.save_session.return_value = Path("results/test.json")

                code, stdout, stderr = self.run_cli(
                    "scan",
                    "127.0.0.1",
                    "--scope",
                    "127.0.0.1",
                )

                self.assertEqual(code, 0)
                self.assertEqual(stderr, "")
                self.assertIn("Result file: results\\test.json", stdout)

                store.save_session.assert_called_once()

                session = store.save_session.call_args.args[0]

                self.assertEqual(session.target, "127.0.0.1")
                self.assertEqual(session.target_type, "ipv4")
                self.assertEqual(session.scope, ("127.0.0.1",))
                self.assertEqual(session.status, "created")

    def test_rejected_scan_does_not_save_session(self):
        with patch("nightrecon.cli.NightReconLogger"):
            with patch("nightrecon.cli.ResultStore") as store_class:
                code, stdout, stderr = self.run_cli(
                    "scan",
                    "192.168.2.25",
                    "--scope",
                    "192.168.1.0/24",
                )

                self.assertEqual(code, 2)
                self.assertEqual(stdout, "")
                self.assertIn("outside the authorized scope", stderr)

                store_class.assert_not_called()

    def test_authorized_scan_writes_created_audit_event(self):
        with patch("nightrecon.cli.ResultStore") as store_class:
            store_class.return_value.save_session.return_value = Path(
                "results/test.json"
            )

            with patch("nightrecon.cli.NightReconLogger") as logger_class:
                logger = logger_class.return_value

                code, stdout, stderr = self.run_cli(
                    "scan",
                    "127.0.0.1",
                    "--scope",
                    "127.0.0.1",
                )

                self.assertEqual(code, 0)
                self.assertEqual(stderr, "")

                logger.write.assert_called_once()

                args, kwargs = logger.write.call_args

                self.assertEqual(args[0], "scan.created")
                self.assertEqual(kwargs["target"], "127.0.0.1")
                self.assertEqual(kwargs["target_type"], "ipv4")
                self.assertEqual(kwargs["scope"], ["127.0.0.1"])
                self.assertEqual(kwargs["status"], "created")
                self.assertIn("session_id", kwargs)

    def test_rejected_scan_writes_rejected_audit_event(self):
        with patch("nightrecon.cli.NightReconLogger") as logger_class:
            logger = logger_class.return_value

            code, stdout, stderr = self.run_cli(
                "scan",
                "127.0.0.2",
                "--scope",
                "127.0.0.1",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("outside the authorized scope", stderr)

            logger.write.assert_called_once_with(
                "scan.rejected",
                target="127.0.0.2",
                target_type="ipv4",
                scope=["127.0.0.1"],
                reason="outside_authorized_scope",
            )

    def test_custom_runtime_configuration_is_applied(self):
        with patch("nightrecon.cli.ResultStore") as store_class:
            store_class.return_value.save_session.return_value = Path(
                "custom-results/test.json"
            )

            with patch("nightrecon.cli.NightReconLogger") as logger_class:
                code, stdout, stderr = self.run_cli(
                    "scan",
                    "127.0.0.1",
                    "--scope",
                    "127.0.0.1",
                    "--timeout",
                    "5",
                    "--workers",
                    "10",
                    "--results-dir",
                    "custom-results",
                    "--logs-dir",
                    "custom-logs",
                )

                self.assertEqual(code, 0)
                self.assertEqual(stderr, "")
                self.assertIn("Connection timeout: 5.0", stdout)
                self.assertIn("Max workers: 10", stdout)

                store_class.assert_called_once_with("custom-results")
                logger_class.assert_called_once_with("custom-logs")

    def test_invalid_runtime_configuration_is_rejected(self):
        with patch("nightrecon.cli.NightReconLogger") as logger_class:
            code, stdout, stderr = self.run_cli(
                "scan",
                "127.0.0.1",
                "--scope",
                "127.0.0.1",
                "--workers",
                "0",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("max_workers must be at least 1", stderr)
            logger_class.assert_not_called()


if __name__ == "__main__":
    unittest.main()
