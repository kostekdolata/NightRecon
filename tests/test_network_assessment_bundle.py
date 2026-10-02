"""Tests for reusable high-level network assessment bundles."""

import unittest

from nightrecon_red_engine.network_assessment_bundle import (
    build_network_assessment_bundle,
)
from nightrecon_red_engine.service_detection import ServiceDetectionResult
from nightrecon_red_engine.tcp_scanner import TcpPortResult


class NetworkAssessmentBundleTests(unittest.TestCase):
    def test_bundle_builds_consistent_high_level_layers(self):
        bundle = build_network_assessment_bundle(
            host="192.0.2.10",
            tcp_results=(
                TcpPortResult(
                    address="192.0.2.10",
                    port=443,
                    is_open=True,
                    error_code=0,
                ),
            ),
            services=(
                ServiceDetectionResult(
                    address="192.0.2.10",
                    port=443,
                    service="https",
                    banner="",
                ),
            ),
        )

        payload = bundle.to_dict()

        self.assertEqual(payload["host"], "192.0.2.10")
        self.assertEqual(
            payload["assessment"]["headline"],
            "Network service exposure observed",
        )
        self.assertIn(
            "Web service exposure",
            " ".join(payload["operator_brief"]["primary_focus_areas"]),
        )
        self.assertEqual(payload["completeness"]["level"], "partial")
        self.assertNotIn("risk_score", str(payload).lower())

    def test_bundle_rejects_blank_host(self):
        with self.assertRaisesRegex(ValueError, "host must not be empty"):
            build_network_assessment_bundle(host="   ")


if __name__ == "__main__":
    unittest.main()
