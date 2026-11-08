"""Offline-only operator report regression coverage."""
from dataclasses import replace
import unittest

from nightrecon_red_engine.network_benchmark import (
    NetworkBenchmarkExpectation,
    ExpectedTcpExposure,
    benchmark_network_observations,
)
from nightrecon_red_engine.network_benchmark_provenance import (
    record_network_benchmark_provenance,
)
from nightrecon_red_engine.network_benchmark_quality_report import (
    render_network_benchmark_quality_report,
)
from nightrecon_red_engine.tcp_scanner import TcpPortResult


class OfflineNetworkBenchmarkQualityReportTests(unittest.TestCase):
    def setUp(self):
        self.expected = NetworkBenchmarkExpectation(
            authorized_addresses=("192.0.2.10",),
            tcp_open=(ExpectedTcpExposure("192.0.2.10", 443),),
        )
        self.found = benchmark_network_observations(
            self.expected,
            tcp_results=(TcpPortResult("192.0.2.10", 443, True, 0),),
        )
        self.missed = benchmark_network_observations(self.expected)
        self.options = {
            "authorization_reference": "engagement-secret-01",
            "environment_sha256": "a" * 64,
            "ground_truth_sha256": "b" * 64,
            "configuration_sha256": "c" * 64,
            "observed_at": "2026-11-08T01:00:00+00:00",
            "comparator_name": "Nmap",
            "comparator_version": "7.95",
        }

    def pair(self, result, run_id):
        return (
            record_network_benchmark_provenance(
                result, lab_run_id=run_id, **self.options,
            ),
            result,
        )

    def test_stable_report_is_redacted_deterministic_and_unverified(self):
        observations = (self.pair(self.found, "first"), self.pair(self.found, "second"))
        report = render_network_benchmark_quality_report(observations)
        self.assertEqual(report, render_network_benchmark_quality_report(observations))
        self.assertIn("consistent_unverified", report)
        self.assertIn("| TCP open | 1–1 | 0–0 | 0–0 |", report)
        self.assertIn("Operator review required:** no", report)
        self.assertIn("Authorization effect:** none", report)
        for secret in ("engagement-secret-01", "192.0.2.10", "first", "second"):
            self.assertNotIn(secret, report)

    def test_changed_runs_show_review_and_quality_drift(self):
        report = render_network_benchmark_quality_report((
            self.pair(self.found, "first"), self.pair(self.missed, "second"),
        ))
        self.assertIn("review_required", report)
        self.assertIn("| TCP open | 0–1 | 0–1 | 0–0 |", report)
        self.assertIn("Investigate", report)

    def test_invalid_and_reused_runs_withhold_all_aggregate_counts(self):
        first = self.pair(self.found, "first")
        second = self.pair(self.found, "second")
        for observations in (
            (first, first),
            (first, (replace(second[0], evidence_fingerprint="0" * 64), second[1])),
            (first, (
                record_network_benchmark_provenance(
                    self.found, lab_run_id="third",
                    **{**self.options, "ground_truth_sha256": "d" * 64},
                ),
                self.found,
            )),
        ):
            with self.subTest(observations=observations):
                report = render_network_benchmark_quality_report(observations)
                self.assertIn("Status:** `blocked`", report)
                self.assertIn("Aggregate results withheld", report)
                self.assertNotIn("| TCP open |", report)
                self.assertIn("Operator review required:** yes", report)

    def test_bounded_input_validation_remains_enforced(self):
        with self.assertRaises(ValueError):
            render_network_benchmark_quality_report((self.pair(self.found, "only"),))
        with self.assertRaises(TypeError):
            render_network_benchmark_quality_report([self.pair(self.found, "first"),
                                                     self.pair(self.found, "second")])


if __name__ == "__main__":
    unittest.main()
