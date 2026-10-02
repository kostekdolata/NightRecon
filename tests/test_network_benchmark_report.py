"""Tests for operator-facing network benchmark reports."""

import unittest

from nightrecon_red_engine.network_benchmark import (
    NetworkBenchmarkResult,
    NETWORK_BENCHMARK_INTERPRETATION,
)
from nightrecon_red_engine.network_benchmark_report import (
    build_network_benchmark_report,
)


def result(**overrides):
    values = dict(
        expected_tcp_open=1,
        matched_tcp_open=1,
        missed_tcp_open=0,
        invented_tcp_open=0,
        expected_udp_open=1,
        matched_udp_open=1,
        missed_udp_open=0,
        invented_udp_open=0,
        ambiguous_udp_expected_open=0,
        expected_services=1,
        matched_services=1,
        missed_services=0,
        invented_services=0,
        expected_operating_systems=1,
        matched_operating_systems=1,
        missed_operating_systems=0,
        conflicting_operating_systems=0,
        scope_violation_count=0,
        scope_violations=(),
        duration_ms=10.0,
        comparison_sha256="a" * 64,
        interpretation=NETWORK_BENCHMARK_INTERPRETATION,
    )
    values.update(overrides)
    return NetworkBenchmarkResult(**values)


class NetworkBenchmarkReportTests(unittest.TestCase):
    def test_clean_match_is_described_without_parity_claim(self):
        report = build_network_benchmark_report(result())

        self.assertIn("matched", report.headline.lower())
        self.assertEqual(report.comparison_sha256, "a" * 64)
        self.assertTrue(any("does not establish" in x for x in report.safety_notes))

    def test_scope_violation_takes_precedence(self):
        report = build_network_benchmark_report(
            result(
                scope_violation_count=1,
                scope_violations=("tcp:198.51.100.5",),
            )
        )

        self.assertIn("scope-boundary violations", report.headline)


if __name__ == "__main__":
    unittest.main()
