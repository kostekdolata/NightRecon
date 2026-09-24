"""Tests for structured NightRecon host-discovery reports."""

import unittest
from unittest.mock import patch

from nightrecon.discovery_report import HostDiscoveryReport
from nightrecon.host_discovery import HostDiscoveryResult
from nightrecon.session import ScanSession
from nightrecon.targets import parse_target


class HostDiscoveryReportTests(unittest.TestCase):
    def test_report_contains_discovery_summary_and_results(self):
        session = ScanSession.create(
            target=parse_target("192.0.2.0/30"),
            scope_rules=("192.0.2.0/24",),
        )

        report = HostDiscoveryReport.create(
            session=session,
            ports_requested=(22, 443),
            max_hosts=32,
            results=(
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
            ),
        )

        data = report.to_dict()

        self.assertEqual(data["target"], "192.0.2.0/30")
        self.assertEqual(data["target_type"], "cidr")
        self.assertEqual(data["ports_requested"], (22, 443))
        self.assertEqual(
            data["network"],
            {
                "normalized_cidr": "192.0.2.0/30",
                "address_family": "ipv4",
                "prefix_length": 30,
                "total_addresses": 4,
                "first_address": "192.0.2.0",
                "last_address": "192.0.2.3",
            },
        )
        self.assertEqual(data["max_hosts"], 32)
        self.assertEqual(
            data["summary"],
            {
                "hosts_tested": 2,
                "responsive_hosts": 1,
                "unresponsive_hosts": 1,
                "named_hosts": 0,
            },
        )
        self.assertEqual(
            data["results"][1]["address"],
            "192.0.2.2",
        )

    def test_responsive_hosts_filters_results(self):
        session = ScanSession.create(
            target=parse_target("192.0.2.0/30"),
            scope_rules=("192.0.2.0/30",),
        )

        report = HostDiscoveryReport.create(
            session=session,
            ports_requested=(443,),
            max_hosts=8,
            results=(
                HostDiscoveryResult(
                    address="192.0.2.1",
                    responsive=True,
                    method="tcp-connect",
                    port=443,
                    observation="tcp-open",
                    error_code=0,
                ),
                HostDiscoveryResult(
                    address="192.0.2.2",
                    responsive=False,
                    method="tcp-connect",
                    port=None,
                    observation="no-response",
                ),
            ),
        )

        self.assertEqual(
            tuple(item.address for item in report.responsive_hosts),
            ("192.0.2.1",),
        )


if __name__ == "__main__":
    unittest.main()
