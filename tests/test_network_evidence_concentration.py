"""Tests for engagement evidence concentration."""

import unittest

from nightrecon_red_engine.network_assessment_bundle import (
    build_network_assessment_bundle,
)
from nightrecon_red_engine.network_evidence_concentration import (
    build_network_evidence_concentration,
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


class NetworkEvidenceConcentrationTests(unittest.TestCase):
    def test_recurring_exposure_categories_are_aggregated(self):
        result = build_network_evidence_concentration(
            (bundle("host-a"), bundle("host-b"))
        )

        self.assertIn(
            ("web-services", 2),
            result.recurring_exposure_categories,
        )
        self.assertEqual(
            result.concentration_hosts[0][1],
            result.concentration_hosts[1][1],
        )
        self.assertNotIn("risk_score", str(result.to_dict()).lower())

    def test_duplicate_hosts_fail_closed(self):
        item = bundle("host-a")

        with self.assertRaisesRegex(
            ValueError,
            "Duplicate host assessment bundle",
        ):
            build_network_evidence_concentration((item, item))

    def test_empty_input_is_explicit(self):
        result = build_network_evidence_concentration(())

        self.assertEqual(result.recurring_exposure_categories, ())
        self.assertIn("No network evidence concentration", result.headline)


if __name__ == "__main__":
    unittest.main()
