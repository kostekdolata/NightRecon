"""Tests for NightRecon scan reports."""

import unittest

from nightrecon.report import TcpScanReport
from nightrecon.session import ScanSession
from nightrecon.targets import parse_target
from nightrecon.tcp_scanner import TcpPortResult


class TcpScanReportTests(unittest.TestCase):
    def create_report(self):
        target = parse_target("127.0.0.1")

        session = ScanSession.create(
            target=target,
            scope_rules=("127.0.0.1",),
        )

        results = (
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

        return TcpScanReport.create(
            session=session,
            resolved_addresses=("127.0.0.1",),
            ports_requested=(80, 443),
            results=results,
        )

    def test_report_is_completed(self):
        report = self.create_report()

        self.assertEqual(report.status, "completed")

    def test_report_preserves_session_data(self):
        report = self.create_report()

        self.assertEqual(report.target, "127.0.0.1")
        self.assertEqual(report.target_type, "ipv4")
        self.assertEqual(report.scope, ("127.0.0.1",))

    def test_report_contains_requested_ports(self):
        report = self.create_report()

        self.assertEqual(
            report.ports_requested,
            (80, 443),
        )

    def test_open_ports_only_returns_open_results(self):
        report = self.create_report()

        self.assertEqual(len(report.open_ports), 1)
        self.assertEqual(report.open_ports[0].port, 80)

    def test_report_converts_to_dictionary(self):
        report = self.create_report()

        data = report.to_dict()

        self.assertEqual(data["status"], "completed")
        self.assertEqual(
            data["resolved_addresses"],
            ("127.0.0.1",),
        )
        self.assertEqual(
            data["ports_requested"],
            (80, 443),
        )
        self.assertEqual(len(data["results"]), 2)
        self.assertEqual(data["results"][0]["port"], 80)
        self.assertTrue(data["results"][0]["is_open"])


if __name__ == "__main__":
    unittest.main()
