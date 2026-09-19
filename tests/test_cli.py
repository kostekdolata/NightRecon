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


if __name__ == "__main__":
    unittest.main()
