"""Tests for engagement-level network executive roll-up."""

import unittest

from nightrecon_red_engine.network_assessment_bundle import (
    build_network_assessment_bundle,
)
from nightrecon_red_engine.network_engagement_executive import (
    build_network_engagement_executive,
)
from nightrecon_red_engine.service_detection import ServiceDetectionResult
from nightrecon_red_engine.tcp_scanner import TcpPortResult


def bundle(host):
    return build_network_assessment_bundle(
        host=host,
        tcp_results=(
            TcpPortResult(
                address=host,
                port=443,
                is_open=True,
                error_code=0,
            ),
        ),
        services=(
            ServiceDetectionResult(
                address=host,
                port=443,
                service="https",
                banner="",
            ),
        ),
    )


class NetworkEngagementExecutiveTests(unittest.TestCase):
    def test_rollup_surfaces_recurring_observations(self):
        result = build_network_engagement_executive(
            (bundle("192.0.2.10"), bundle("192.0.2.20"))
        )

        self.assertEqual(result.hosts_assessed, 2)
        self.assertTrue(result.recurring_observations)
        self.assertTrue(any(
            "Web service exposure" in observation
            and count == 2
            for observation, count in result.recurring_observations
        ))
        self.assertIn(("partial", 2), result.completeness_counts)

    def test_duplicate_hosts_fail_closed(self):
        first = bundle("192.0.2.10")

        with self.assertRaisesRegex(
            ValueError,
            "Duplicate host assessment bundle",
        ):
            build_network_engagement_executive((first, first))

    def test_empty_rollup_is_explicitly_incomplete(self):
        result = build_network_engagement_executive(())

        self.assertEqual(result.hosts_assessed, 0)
        self.assertIn("No network assessment bundles", result.headline)


if __name__ == "__main__":
    unittest.main()
