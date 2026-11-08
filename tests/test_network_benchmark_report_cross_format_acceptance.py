"""End-to-end offline acceptance: operator Markdown and portable JSON agree.

All observations are synthetic; no sockets, scanners or credentials are used.
"""
from dataclasses import replace
import json
import unittest

from nightrecon_red_engine.network_benchmark import (
    ExpectedTcpExposure, NetworkBenchmarkExpectation, benchmark_network_observations,
)
from nightrecon_red_engine.network_benchmark_provenance import record_network_benchmark_provenance
from nightrecon_red_engine.network_benchmark_quality_export import render_network_benchmark_quality_json
from nightrecon_red_engine.network_benchmark_quality_report import render_network_benchmark_quality_report
from nightrecon_red_engine.tcp_scanner import TcpPortResult


class OfflineReportCrossFormatAcceptanceTests(unittest.TestCase):
    def setUp(self):
        expected = NetworkBenchmarkExpectation(
            authorized_addresses=("192.0.2.10",),
            tcp_open=(ExpectedTcpExposure("192.0.2.10", 443),),
        )
        self.match = benchmark_network_observations(
            expected, tcp_results=(TcpPortResult("192.0.2.10", 443, True, 0),),
        )
        self.miss = benchmark_network_observations(expected)
        self.provenance_options = dict(
            authorization_reference="private-authorization-reference",
            environment_sha256="a" * 64,
            ground_truth_sha256="b" * 64,
            configuration_sha256="c" * 64,
            observed_at="2026-11-08T01:00:00+00:00",
            comparator_name="PrivateComparator",
            comparator_version="1.0",
        )

    def pair(self, result, run_id):
        return (
            record_network_benchmark_provenance(
                result, lab_run_id=run_id, **self.provenance_options,
            ),
            result,
        )

    def assert_consistent_outputs(self, observations, expected_status, metrics_visible):
        markdown = render_network_benchmark_quality_report(observations)
        portable = render_network_benchmark_quality_json(observations)
        payload = json.loads(portable)
        self.assertEqual(payload["status"], expected_status)
        self.assertIn("**Status:** `" + expected_status + "`", markdown)
        self.assertEqual(payload["observation_count"], len(observations))
        self.assertIn(f"**Submitted observations:** {len(observations)}", markdown)
        self.assertIn("**Authorization effect:** none", markdown)
        self.assertEqual(payload["authorization_effect"], "none")
        self.assertEqual(payload["aggregate_metrics"] is not None, metrics_visible)
        if metrics_visible:
            self.assertIn("| TCP open |", markdown)
            self.assertNotIn("Aggregate results withheld", markdown)
        else:
            self.assertIn("Aggregate results withheld", markdown)
            self.assertNotIn("| TCP open |", markdown)
        for sensitive in (
            "192.0.2.10", "private-authorization-reference",
            "PrivateComparator", "unique-first", "unique-second",
        ):
            self.assertNotIn(sensitive, markdown)
            self.assertNotIn(sensitive, portable)
        self.assertEqual(markdown, render_network_benchmark_quality_report(observations))
        self.assertEqual(portable, render_network_benchmark_quality_json(observations))
        return payload

    def test_stable_observations_agree_without_claiming_external_validation(self):
        observations = (
            self.pair(self.match, "unique-first"),
            self.pair(self.match, "unique-second"),
        )
        payload = self.assert_consistent_outputs(observations, "consistent_unverified", True)
        self.assertEqual(payload["aggregate_metrics"]["matched_tcp_open"], {"min": 1, "max": 1})
        self.assertTrue(any("not independently verified" in x for x in payload["limitations"]))

    def test_drift_requires_review_in_both_formats(self):
        observations = (
            self.pair(self.match, "unique-first"),
            self.pair(self.miss, "unique-second"),
        )
        payload = self.assert_consistent_outputs(observations, "review_required", True)
        self.assertTrue(payload["requires_review"])
        self.assertEqual(payload["aggregate_metrics"]["matched_tcp_open"], {"min": 0, "max": 1})
        self.assertIn("Observations changed", render_network_benchmark_quality_report(observations))

    def test_duplicate_and_tampered_evidence_fail_closed_in_both_formats(self):
        first = self.pair(self.match, "unique-first")
        second = self.pair(self.match, "unique-second")
        cases = (
            (first, first),
            (first, (replace(second[0], evidence_fingerprint="0" * 64), second[1])),
        )
        for observations in cases:
            with self.subTest(observations=observations):
                payload = self.assert_consistent_outputs(observations, "blocked", False)
                self.assertIsNone(payload["aggregate_metrics"])
                self.assertTrue(payload["requires_review"])


if __name__ == "__main__":
    unittest.main()
