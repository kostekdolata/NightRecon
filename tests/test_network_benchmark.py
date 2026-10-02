"""Tests for deterministic network benchmark evidence."""

import unittest

from nightrecon_red_engine.network_benchmark import (
    ExpectedOperatingSystem,
    ExpectedService,
    ExpectedTcpExposure,
    ExpectedUdpExposure,
    NetworkBenchmarkExpectation,
    benchmark_network_observations,
)
from nightrecon_red_engine.os_fingerprint import (
    HostOperatingSystemFingerprint,
    OperatingSystemFingerprint,
)
from nightrecon_red_engine.service_detection import ServiceDetectionResult
from nightrecon_red_engine.tcp_scanner import TcpPortResult
from nightrecon_red_engine.udp_scanner import UdpPortResult


class NetworkBenchmarkTests(unittest.TestCase):
    def test_ipv4_ipv6_coverage_false_positive_and_udp_ambiguity(self):
        expectation = NetworkBenchmarkExpectation(
            authorized_addresses=("192.0.2.10", "2001:db8::10"),
            tcp_open=(
                ExpectedTcpExposure("192.0.2.10", 443),
                ExpectedTcpExposure("2001:db8::10", 22),
            ),
            udp_open=(ExpectedUdpExposure("192.0.2.10", 53),),
            services=(ExpectedService("192.0.2.10", 443, "https"),),
            operating_systems=(
                ExpectedOperatingSystem("2001:0db8:0:0:0:0:0:10", "Ubuntu"),
            ),
        )

        result = benchmark_network_observations(
            expectation,
            tcp_results=(
                TcpPortResult("192.0.2.10", 443, True, 0),
                TcpPortResult("2001:db8::10", 22, False, 111),
                TcpPortResult("192.0.2.10", 8080, True, 0),
            ),
            udp_results=(
                UdpPortResult(
                    "192.0.2.10",
                    53,
                    "open|filtered",
                    service_hint="dns",
                ),
            ),
            services=(
                ServiceDetectionResult(
                    "192.0.2.10", 443, "https", "", error_code=0
                ),
            ),
            operating_system_fingerprints=(
                HostOperatingSystemFingerprint(
                    "2001:db8::10",
                    OperatingSystemFingerprint(
                        platform="Ubuntu",
                        family="Linux",
                        confidence="medium",
                    ),
                ),
            ),
            duration_ms=12.5,
        )

        self.assertEqual(result.matched_tcp_open, 1)
        self.assertEqual(result.missed_tcp_open, 1)
        self.assertEqual(result.invented_tcp_open, 1)
        self.assertEqual(result.matched_udp_open, 0)
        self.assertEqual(result.missed_udp_open, 1)
        self.assertEqual(result.ambiguous_udp_expected_open, 1)
        self.assertEqual(result.matched_services, 1)
        self.assertEqual(result.matched_operating_systems, 1)
        self.assertEqual(result.scope_violation_count, 0)
        self.assertFalse(result.expected_coverage_complete)
        self.assertTrue(result.unexpected_evidence_present)

    def test_scope_violation_counts_closed_tcp_observation(self):
        result = benchmark_network_observations(
            NetworkBenchmarkExpectation(
                authorized_addresses=("192.0.2.10",),
            ),
            tcp_results=(
                TcpPortResult("198.51.100.20", 443, False, 111),
            ),
        )

        self.assertEqual(result.scope_violation_count, 1)
        self.assertEqual(
            result.scope_violations,
            ("tcp:198.51.100.20",),
        )

    def test_runtime_is_excluded_from_fingerprint(self):
        expectation = NetworkBenchmarkExpectation(
            authorized_addresses=("192.0.2.10",),
            tcp_open=(ExpectedTcpExposure("192.0.2.10", 443),),
        )
        observed = (TcpPortResult("192.0.2.10", 443, True, 0),)

        first = benchmark_network_observations(
            expectation, tcp_results=observed, duration_ms=1.0
        )
        second = benchmark_network_observations(
            expectation, tcp_results=observed, duration_ms=999.0
        )

        self.assertEqual(first.comparison_sha256, second.comparison_sha256)
        self.assertNotEqual(first.duration_ms, second.duration_ms)
        self.assertNotIn("parity", first.interpretation.lower().split("do not establish")[0])


if __name__ == "__main__":
    unittest.main()
