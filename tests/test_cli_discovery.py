"""CLI integration tests for NightRecon host discovery."""

import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from nightrecon.cli import main
from nightrecon.host_discovery import HostDiscoveryResult


class CliHostDiscoveryTests(unittest.TestCase):
    def test_discover_runs_authorized_cidr_and_persists_report(self):
        results = (
            HostDiscoveryResult(
                address="192.0.2.1",
                responsive=False,
                method="tcp-connect",
                port=None,
                observation="no-response",
            ),
            HostDiscoveryResult(
                address="192.0.2.2",
                responsive=True,
                method="tcp-connect",
                port=443,
                observation="tcp-open",
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
                "discover",
                "192.0.2.0/30",
                "--scope",
                "192.0.2.0/24",
                "--ports",
                "22,443",
                "--timeout",
                "0.5",
                "--workers",
                "8",
                "--max-hosts",
                "16",
                "--results-dir",
                "results-test",
                "--logs-dir",
                "logs-test",
            ],
        ):
            with patch(
                "nightrecon.cli.discover_hosts",
                return_value=results,
            ) as discover:
                with patch(
                    "nightrecon.cli.ResultStore"
                ) as store_class:
                    store_class.return_value.save_discovery_report.return_value = (
                        Path("results-test/discovery.json")
                    )

                    with patch(
                        "nightrecon.cli.NightReconLogger"
                    ) as logger_class:
                        with contextlib.redirect_stdout(stdout):
                            with contextlib.redirect_stderr(stderr):
                                main()

        self.assertEqual(stderr.getvalue(), "")
        discover.assert_called_once_with(
            cidr="192.0.2.0/30",
            ports=(22, 443),
            timeout=0.5,
            max_workers=8,
            max_hosts=16,
        )
        store_class.assert_called_once_with(
            "results-test"
        )
        logger_class.assert_called_once_with(
            "logs-test"
        )

        report = (
            store_class.return_value
            .save_discovery_report
            .call_args.args[0]
        )
        self.assertEqual(report.target, "192.0.2.0/30")
        self.assertEqual(report.scope, ("192.0.2.0/24",))
        self.assertEqual(report.results, results)

        output = stdout.getvalue()
        self.assertIn(
            "NightRecon discovery target: 192.0.2.0/30",
            output,
        )
        self.assertIn(
            "Hosts tested: 2",
            output,
        )
        self.assertIn(
            "Responsive hosts: 1",
            output,
        )
        self.assertIn(
            "RESPONSIVE 192.0.2.2 method=tcp-connect "
            "observation=tcp-open port=443",
            output,
        )
        self.assertIn(
            "Result file: results-test/discovery.json",
            output,
        )

    def test_discover_rejects_out_of_scope_cidr_before_probing(self):
        stderr = io.StringIO()

        with patch.object(
            sys,
            "argv",
            [
                "nightrecon",
                "discover",
                "192.0.2.0/24",
                "--scope",
                "192.0.2.0/28",
            ],
        ):
            with patch(
                "nightrecon.cli.discover_hosts"
            ) as discover:
                with patch(
                    "nightrecon.cli.NightReconLogger"
                ):
                    with contextlib.redirect_stderr(stderr):
                        with self.assertRaises(SystemExit) as exc:
                            main()

        self.assertEqual(exc.exception.code, 2)
        self.assertIn(
            "outside the authorized scope",
            stderr.getvalue(),
        )
        discover.assert_not_called()

    def test_discover_requires_cidr_target(self):
        stderr = io.StringIO()

        with patch.object(
            sys,
            "argv",
            [
                "nightrecon",
                "discover",
                "192.0.2.10",
                "--scope",
                "192.0.2.0/24",
            ],
        ):
            with patch(
                "nightrecon.cli.discover_hosts"
            ) as discover:
                with patch(
                    "nightrecon.cli.NightReconLogger"
                ):
                    with contextlib.redirect_stderr(stderr):
                        with self.assertRaises(SystemExit) as exc:
                            main()

        self.assertEqual(exc.exception.code, 2)
        self.assertIn(
            "discover requires a CIDR target",
            stderr.getvalue(),
        )
        discover.assert_not_called()

    def test_discover_reports_bounded_host_limit_errors(self):
        stderr = io.StringIO()

        with patch.object(
            sys,
            "argv",
            [
                "nightrecon",
                "discover",
                "192.0.2.0/24",
                "--scope",
                "192.0.2.0/24",
                "--max-hosts",
                "4",
            ],
        ):
            with patch(
                "nightrecon.cli.discover_hosts",
                side_effect=ValueError(
                    "CIDR host count exceeds max_hosts=4."
                ),
            ):
                with patch(
                    "nightrecon.cli.NightReconLogger"
                ):
                    with contextlib.redirect_stderr(stderr):
                        with self.assertRaises(SystemExit) as exc:
                            main()

        self.assertEqual(exc.exception.code, 2)
        self.assertIn(
            "CIDR host count exceeds max_hosts=4",
            stderr.getvalue(),
        )


if __name__ == "__main__":
    unittest.main()
