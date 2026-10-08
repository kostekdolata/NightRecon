"""Tests for high-level Red Night network assessment intelligence."""

import unittest

from nightrecon_red_engine.network_assessment_intelligence import (
    NETWORK_INTELLIGENCE_INTERPRETATION,
    build_network_assessment_intelligence,
)
from nightrecon_red_engine.service_detection import ServiceDetectionResult
from nightrecon_red_engine.tcp_scanner import TcpPortResult
from nightrecon_red_engine.udp_scanner import UdpPortResult


class NetworkAssessmentIntelligenceTests(unittest.TestCase):
    def test_broad_exposure_produces_high_level_operator_feedback(self):
        intelligence = build_network_assessment_intelligence(
            tcp_results=(
                TcpPortResult("192.0.2.10", 22, True, 0),
                TcpPortResult("192.0.2.10", 445, True, 0),
                TcpPortResult("192.0.2.10", 443, True, 0),
            ),
            services=(
                ServiceDetectionResult(
                    address="192.0.2.10",
                    port=22,
                    service="ssh",
                    banner="SSH-2.0-example",
                ),
                ServiceDetectionResult(
                    address="192.0.2.10",
                    port=445,
                    service="smb",
                    banner="",
                ),
                ServiceDetectionResult(
                    address="192.0.2.10",
                    port=443,
                    service="https",
                    banner="",
                ),
            ),
            udp_results=(
                UdpPortResult(
                    address="192.0.2.10",
                    port=53,
                    state="open",
                    service_hint="dns",
                    confidence="high",
                    protocol_match=True,
                ),
            ),
        )

        self.assertEqual(
            intelligence.headline,
            "Broad network service exposure observed",
        )
        self.assertEqual(intelligence.confidence, "high")
        self.assertTrue(any(
            "Remote administration" in item
            for item in intelligence.notable_exposures
        ))
        self.assertTrue(any(
            "Data or file-service exposure" in item
            for item in intelligence.notable_exposures
        ))
        self.assertTrue(any(
            "Web-facing services" in item
            for item in intelligence.notable_exposures
        ))
        self.assertIn(
            "do not by themselves establish a vulnerability",
            intelligence.interpretation,
        )

    def test_coverage_gaps_reduce_confidence_without_overclaiming(self):
        intelligence = build_network_assessment_intelligence(
            tcp_results=(
                TcpPortResult("192.0.2.10", 8081, True, 0),
            ),
            udp_results=(
                UdpPortResult(
                    address="192.0.2.10",
                    port=161,
                    state="open|filtered",
                    service_hint="snmp",
                    attempts=2,
                ),
            ),
        )

        self.assertEqual(
            intelligence.headline,
            "Network service exposure observed",
        )
        self.assertEqual(intelligence.confidence, "limited")
        self.assertTrue(any(
            "open|filtered" in item
            for item in intelligence.coverage_gaps
        ))
        self.assertTrue(any(
            "lack service identification" in item
            for item in intelligence.coverage_gaps
        ))
        self.assertFalse(any(
            "vulnerable" in item.lower()
            for item in intelligence.notable_exposures
        ))

    def test_no_response_is_reported_as_coverage_not_safety(self):
        intelligence = build_network_assessment_intelligence()

        self.assertEqual(
            intelligence.headline,
            "No responsive network services confirmed",
        )
        self.assertEqual(intelligence.confidence, "limited")
        self.assertIn(
            "not proof that the host has no network exposure",
            intelligence.overview,
        )
        self.assertEqual(
            intelligence.interpretation,
            NETWORK_INTELLIGENCE_INTERPRETATION,
        )

    def test_output_is_serializable_and_high_level(self):
        intelligence = build_network_assessment_intelligence(
            tcp_results=(
                TcpPortResult("192.0.2.10", 3389, True, 0),
            ),
            services=(
                ServiceDetectionResult(
                    address="192.0.2.10",
                    port=3389,
                    service="rdp",
                    banner="",
                ),
            ),
        )

        payload = intelligence.to_dict()

        self.assertEqual(
            payload["headline"],
            "Network service exposure observed",
        )
        self.assertIn("recommended_next_actions", payload)
        self.assertNotIn("risk_score", str(payload).lower())
        self.assertNotIn("exploitability", payload["headline"].lower())


    def test_filtered_and_error_tcp_are_coverage_gaps_not_closed_ports(self):
        intelligence = build_network_assessment_intelligence(
            tcp_results=(
                TcpPortResult(
                    "192.0.2.10",
                    443,
                    False,
                    10060,
                    state="filtered",
                    confidence="medium",
                ),
                TcpPortResult(
                    "192.0.2.10",
                    445,
                    False,
                    10051,
                    state="error",
                    confidence="low",
                ),
            ),
        )

        self.assertEqual(intelligence.confidence, "limited")
        self.assertTrue(any(
            "remain filtered" in item
            for item in intelligence.coverage_gaps
        ))
        self.assertTrue(any(
            "could not be classified" in item
            for item in intelligence.coverage_gaps
        ))
        self.assertTrue(any(
            "before treating affected ports as closed" in item
            for item in intelligence.recommended_next_actions
        ))


if __name__ == "__main__":
    unittest.main()
