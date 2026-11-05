"""Reproducible non-authoritative lab benchmark provenance tests."""
import unittest

from nightrecon_red_engine.network_benchmark import (
    NetworkBenchmarkExpectation, benchmark_network_observations,
)
from nightrecon_red_engine.network_benchmark_provenance import (
    record_network_benchmark_provenance,
)
from nightrecon_red_engine.tcp_scanner import TcpPortResult


class NetworkBenchmarkProvenanceTests(unittest.TestCase):
    def setUp(self):
        expectation = NetworkBenchmarkExpectation(
            authorized_addresses=("192.0.2.10",),
        )
        self.result = benchmark_network_observations(
            expectation,
            tcp_results=(TcpPortResult("198.51.100.20", 443, False, 111),),
        )
        self.options = {
            "lab_run_id": "lab-01",
            "authorization_reference": "engagement-01",
            "environment_sha256": "a" * 64,
            "ground_truth_sha256": "b" * 64,
            "configuration_sha256": "c" * 64,
            "observed_at": "2026-11-05T19:00:00+00:00",
            "comparator_name": "Nmap",
            "comparator_version": "7.95",
        }

    def record(self, **changes):
        return record_network_benchmark_provenance(
            self.result, **{**self.options, **changes},
        )

    def test_record_contains_no_authorization_effect_or_parity_claim(self):
        report = self.record().to_dict()
        self.assertEqual(report["authorization_effect"], "none")
        self.assertEqual(report["scope_violation_count"], 1)
        self.assertEqual(report["comparator_name"], "Nmap")
        self.assertEqual(report["benchmark_sha256"], self.result.comparison_sha256)
        self.assertIn("not independent proof", report["interpretation"])
        self.assertNotIn("credentials", report)
        self.assertEqual(len(report["evidence_fingerprint"]), 64)

    def test_same_evidence_produces_same_stable_fingerprint(self):
        baseline = self.record()
        duplicate = self.record(
            lab_run_id="lab-02",
            observed_at="2026-11-06T20:00:00+00:00",
        )
        self.assertEqual(baseline.evidence_fingerprint, duplicate.evidence_fingerprint)
        changed = self.record(configuration_sha256="d" * 64)
        self.assertNotEqual(baseline.evidence_fingerprint, changed.evidence_fingerprint)

    def test_missing_ground_truth_digest_and_unmatched_comparator_fail(self):
        with self.assertRaisesRegex(ValueError, "ground_truth_sha256"):
            self.record(ground_truth_sha256="")
        with self.assertRaisesRegex(ValueError, "supplied together"):
            self.record(comparator_version=None)
        with self.assertRaisesRegex(ValueError, "metadata"):
            self.record(comparator_name="Nmap\nprivate-key: secret")
        with self.assertRaisesRegex(ValueError, "reference"):
            self.record(authorization_reference="")

    def test_invalid_timestamp_fails_closed(self):
        for stamp in ("2026-11-05T19:00:00", "invalid", None):
            with self.subTest(stamp=stamp), self.assertRaises(ValueError):
                self.record(observed_at=stamp)

    def test_no_comparator_does_not_invent_a_baseline(self):
        report = self.record(
            comparator_name=None, comparator_version=None,
        ).to_dict()
        self.assertIsNone(report["comparator_name"])
        self.assertIsNone(report["comparator_version"])
        self.assertIn("not independent proof", report["interpretation"])


if __name__ == "__main__":
    unittest.main()
