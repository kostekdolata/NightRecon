"""Tests for high-level network evidence completeness."""

import unittest

from nightrecon_red_engine.network_evidence_completeness import (
    build_network_evidence_completeness,
)
from nightrecon_red_engine.service_detection import ServiceDetectionResult
from nightrecon_red_engine.tcp_scanner import TcpPortResult


class NetworkEvidenceCompletenessTests(unittest.TestCase):
    def test_complete_network_and_service_layers_without_enrichment_is_partial(self):
        result = build_network_evidence_completeness(
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

        self.assertEqual(result.level, "partial")
        self.assertIn("network-exposure", result.completed_layers)
        self.assertIn("service-identification", result.completed_layers)
        self.assertIn(
            "vulnerability-intelligence",
            result.missing_layers,
        )
        self.assertIn("threat-context", result.missing_layers)

    def test_missing_service_identification_is_explicit(self):
        result = build_network_evidence_completeness(
            tcp_results=(
                TcpPortResult(
                    address="192.0.2.10",
                    port=8443,
                    is_open=True,
                    error_code=0,
                ),
            ),
        )

        self.assertIn("service-identification", result.missing_layers)
        self.assertTrue(any(
            "lack successful service identification" in note
            for note in result.evidence_notes
        ))

    def test_all_core_layers_are_comprehensive(self):
        result = build_network_evidence_completeness(
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
            vulnerability_intelligence_enabled=True,
            threat_context_enabled=True,
        )

        self.assertEqual(result.level, "comprehensive")
        self.assertFalse(result.missing_layers)


if __name__ == "__main__":
    unittest.main()
