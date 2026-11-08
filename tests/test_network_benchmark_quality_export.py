"""Regression tests for the offline quality report's portable export contract."""
from dataclasses import replace
import json
import unittest

from nightrecon_red_engine.network_benchmark import (
    ExpectedTcpExposure, NetworkBenchmarkExpectation, benchmark_network_observations,
)
from nightrecon_red_engine.network_benchmark_provenance import record_network_benchmark_provenance
from nightrecon_red_engine.network_benchmark_quality_export import (
    build_network_benchmark_quality_export, render_network_benchmark_quality_json,
)
from nightrecon_red_engine.tcp_scanner import TcpPortResult


class OfflineNetworkBenchmarkQualityExportTests(unittest.TestCase):
    def setUp(self):
        expectation = NetworkBenchmarkExpectation(
            authorized_addresses=("192.0.2.10",),
            tcp_open=(ExpectedTcpExposure("192.0.2.10", 443),),
        )
        self.found = benchmark_network_observations(
            expectation, tcp_results=(TcpPortResult("192.0.2.10", 443, True, 0),),
        )
        self.missed = benchmark_network_observations(expectation)
        self.options = dict(
            authorization_reference="sensitive-engagement-token",
            environment_sha256="a" * 64,
            ground_truth_sha256="b" * 64,
            configuration_sha256="c" * 64,
            observed_at="2026-11-08T01:00:00+00:00",
            comparator_name="Nmap", comparator_version="7.95",
        )

    def pair(self, result, run_id):
        return (record_network_benchmark_provenance(
            result, lab_run_id=run_id, **self.options,
        ), result)

    def test_stable_export_is_versioned_deterministic_redacted(self):
        pairs = (self.pair(self.found, "unique-first"), self.pair(self.found, "unique-second"))
        payload = render_network_benchmark_quality_json(pairs)
        self.assertEqual(payload, render_network_benchmark_quality_json(pairs))
        result = json.loads(payload)
        self.assertEqual(result["schema_version"], 1)
        self.assertEqual(result["status"], "consistent_unverified")
        self.assertEqual(result["aggregate_metrics"]["matched_tcp_open"], {"min": 1, "max": 1})
        self.assertEqual(result["authorization_effect"], "none")
        self.assertEqual(len(result["aggregate_metrics"]), 12)
        for sensitive in ("192.0.2.10", "sensitive-engagement-token",
                          "unique-first", "unique-second", "Nmap", "7.95"):
            self.assertNotIn(sensitive, payload)

    def test_changed_observations_require_review_without_claiming_parity(self):
        data = build_network_benchmark_quality_export((
            self.pair(self.found, "one"), self.pair(self.missed, "two"),
        ))
        self.assertEqual(data["status"], "review_required")
        self.assertTrue(data["requires_review"])
        self.assertEqual(data["aggregate_metrics"]["matched_tcp_open"], {"min": 0, "max": 1})
        self.assertTrue(any("parity" in item for item in data["limitations"]))

    def test_untrusted_or_nonindependent_series_withholds_every_metric(self):
        first = self.pair(self.found, "first")
        second = self.pair(self.found, "second")
        incompatible = (record_network_benchmark_provenance(
            self.found, lab_run_id="third",
            **{**self.options, "ground_truth_sha256": "d" * 64},
        ), self.found)
        for observations in (
            (first, first),
            (first, (replace(second[0], evidence_fingerprint="0" * 64), second[1])),
            (first, incompatible),
        ):
            with self.subTest(observations=observations):
                data = build_network_benchmark_quality_export(observations)
                self.assertEqual(data["status"], "blocked")
                self.assertIsNone(data["aggregate_metrics"])
                self.assertTrue(data["requires_review"])

    def test_invalid_container_and_series_bounds_rejected(self):
        with self.assertRaises(TypeError):
            render_network_benchmark_quality_json([
                self.pair(self.found, "one"), self.pair(self.found, "two"),
            ])
        with self.assertRaises(ValueError):
            render_network_benchmark_quality_json((self.pair(self.found, "only"),))


if __name__ == "__main__":
    unittest.main()
