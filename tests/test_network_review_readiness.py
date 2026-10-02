"""Tests for network engagement review readiness."""

import unittest

from nightrecon_red_engine.network_assessment_bundle import (
    build_network_assessment_bundle,
)
from nightrecon_red_engine.network_review_readiness import (
    build_network_review_readiness,
)
from nightrecon_red_engine.service_detection import ServiceDetectionResult
from nightrecon_red_engine.tcp_scanner import TcpPortResult


def partial_bundle(host):
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


class NetworkReviewReadinessTests(unittest.TestCase):
    def test_partial_evidence_is_not_ready(self):
        result = build_network_review_readiness(
            (partial_bundle("192.0.2.10"),)
        )

        self.assertEqual(result.level, "not-ready")
        self.assertEqual(
            result.hosts_needing_more_evidence,
            ("192.0.2.10",),
        )
        self.assertTrue(result.recurring_missing_layers)

    def test_empty_engagement_is_not_ready(self):
        result = build_network_review_readiness(())

        self.assertEqual(result.level, "not-ready")
        self.assertEqual(result.hosts_assessed, 0)

    def test_duplicate_hosts_fail_closed(self):
        item = partial_bundle("192.0.2.10")

        with self.assertRaisesRegex(
            ValueError,
            "Duplicate host assessment bundle",
        ):
            build_network_review_readiness((item, item))


if __name__ == "__main__":
    unittest.main()
