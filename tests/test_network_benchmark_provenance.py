"""Reproducible non-authoritative lab benchmark provenance tests."""
import unittest

from nightrecon_red_engine.network_benchmark import (
    NetworkBenchmarkExpectation, benchmark_network_observations,
)
from nightrecon_red_engine.network_benchmark_provenance import (
    record_network_benchmark_provenance,
    verify_network_benchmark_provenance,
    report_network_benchmark_provenance_status,
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

    def test_fingerprint_binds_scope_violation_labels(self):
        from dataclasses import replace

        baseline = self.record()
        other = record_network_benchmark_provenance(
            replace(self.result, scope_violations=("udp:198.51.100.20",)),
            **self.options,
        )
        self.assertEqual(baseline.benchmark_sha256, other.benchmark_sha256)
        self.assertEqual(baseline.scope_violation_count, other.scope_violation_count)
        self.assertNotEqual(baseline.evidence_fingerprint, other.evidence_fingerprint)
        self.assertEqual(baseline.to_dict()["schema"], 2)

    def test_scope_evidence_fingerprint_is_repeatable(self):
        from dataclasses import replace

        repeated = record_network_benchmark_provenance(
            replace(self.result, scope_violations=tuple(self.result.scope_violations)),
            **{**self.options, "lab_run_id": "lab-other"},
        )
        self.assertEqual(self.record().evidence_fingerprint, repeated.evidence_fingerprint)

    def test_offline_verifier_accepts_matching_record(self):
        self.assertTrue(verify_network_benchmark_provenance(
            self.record(), self.result,
        ))

    def test_offline_verifier_rejects_tampered_metadata_and_evidence(self):
        from dataclasses import replace

        record = self.record()
        for changed in (
            replace(record, evidence_fingerprint="0" * 64),
            replace(record, benchmark_sha256="0" * 64),
            replace(record, scope_violation_count=0),
            replace(record, comparator_version="7.94"),
            replace(record, authorization_reference="different-engagement"),
            replace(record, observed_at="not-a-timestamp"),
        ):
            with self.subTest(changed=changed):
                self.assertFalse(verify_network_benchmark_provenance(
                    changed, self.result,
                ))
        altered_result = replace(
            self.result, scope_violations=("udp:198.51.100.20",),
        )
        self.assertFalse(verify_network_benchmark_provenance(
            record, altered_result,
        ))

    def test_offline_verifier_rejects_wrong_input_types(self):
        with self.assertRaises(TypeError):
            verify_network_benchmark_provenance({}, self.result)
        with self.assertRaises(TypeError):
            verify_network_benchmark_provenance(self.record(), {})

    def test_offline_report_status_preserves_scope_warning(self):
        report = report_network_benchmark_provenance_status(
            self.record(), self.result,
        )
        self.assertEqual(report["status"], "scope_violations_observed")
        self.assertTrue(report["consistent"])
        self.assertEqual(report["scope_violation_count"], 1)
        self.assertEqual(report["authorization_effect"], "none")
        self.assertIn("not independent proof", report["interpretation"])

    def test_offline_report_status_rejects_tampering(self):
        from dataclasses import replace

        report = report_network_benchmark_provenance_status(
            replace(self.record(), evidence_fingerprint="0" * 64),
            self.result,
        )
        self.assertEqual(report["status"], "inconsistent")
        self.assertFalse(report["consistent"])
        self.assertIsNone(report["scope_violation_count"])

    def test_offline_report_status_clean_does_not_claim_authorization(self):
        clean_result = benchmark_network_observations(
            NetworkBenchmarkExpectation(
                authorized_addresses=("192.0.2.10",),
            ),
            tcp_results=(TcpPortResult("192.0.2.10", 443, False, 111),),
        )
        record = record_network_benchmark_provenance(
            clean_result, **self.options,
        )
        report = report_network_benchmark_provenance_status(
            record, clean_result,
        )
        self.assertEqual(report["status"], "consistent_unverified")
        self.assertEqual(report["scope_violation_count"], 0)
        self.assertEqual(report["authorization_effect"], "none")

    def test_status_links_only_matching_evidence_fingerprint(self):
        from dataclasses import replace

        record = self.record()
        valid = report_network_benchmark_provenance_status(record, self.result)
        self.assertEqual(valid["evidence_fingerprint"], record.evidence_fingerprint)
        self.assertEqual(valid["status"], "scope_violations_observed")

        tampered = report_network_benchmark_provenance_status(
            replace(record, evidence_fingerprint="0" * 64), self.result,
        )
        self.assertEqual(tampered["status"], "inconsistent")
        self.assertIsNone(tampered["evidence_fingerprint"])

        changed_observations = report_network_benchmark_provenance_status(
            record, replace(self.result, scope_violations=("udp:198.51.100.20",)),
        )
        self.assertEqual(changed_observations["status"], "inconsistent")
        self.assertIsNone(changed_observations["evidence_fingerprint"])

    def test_evidence_summary_exports_only_consistent_metrics(self):
        from nightrecon_red_engine.network_benchmark_provenance import (
            report_network_benchmark_evidence_summary,
        )

        report = report_network_benchmark_evidence_summary(
            self.record(), self.result,
        )
        self.assertEqual(report["type"], "network-benchmark-evidence-summary")
        self.assertEqual(report["metrics"]["scope_violation_count"], 1)
        self.assertEqual(
            report["provenance_status"]["status"],
            "scope_violations_observed",
        )
        self.assertEqual(report["authorization_effect"], "none")
        self.assertNotIn("scope_violations", report["metrics"])

    def test_evidence_summary_fails_closed_on_mismatch(self):
        from dataclasses import replace
        from nightrecon_red_engine.network_benchmark_provenance import (
            report_network_benchmark_evidence_summary,
        )

        report = report_network_benchmark_evidence_summary(
            replace(self.record(), evidence_fingerprint="0" * 64),
            self.result,
        )
        self.assertEqual(report["provenance_status"]["status"], "inconsistent")
        self.assertIsNone(report["provenance_status"]["evidence_fingerprint"])
        self.assertIsNone(report["metrics"])
        other = report_network_benchmark_evidence_summary(
            self.record(),
            replace(self.result, scope_violations=("udp:198.51.100.20",)),
        )
        self.assertIsNone(other["metrics"])

    def test_clean_evidence_summary_remains_unverified(self):
        from nightrecon_red_engine.network_benchmark_provenance import (
            report_network_benchmark_evidence_summary,
        )

        clean = benchmark_network_observations(
            NetworkBenchmarkExpectation(authorized_addresses=("192.0.2.10",)),
        )
        record = record_network_benchmark_provenance(clean, **self.options)
        report = report_network_benchmark_evidence_summary(record, clean)
        self.assertEqual(
            report["provenance_status"]["status"], "consistent_unverified",
        )
        self.assertEqual(report["metrics"]["scope_violation_count"], 0)
        self.assertIn("not independent verification", report["interpretation"])

    def test_missing_ground_truth_digest_and_unmatched_comparator_fail(self):
        with self.assertRaisesRegex(ValueError, "ground_truth_sha256"):
            self.record(ground_truth_sha256="")
        with self.assertRaisesRegex(ValueError, "supplied together"):
            self.record(comparator_version=None)
        with self.assertRaisesRegex(ValueError, "metadata"):
            self.record(comparator_name="Nmap\nprivate-key: secret")
        with self.assertRaisesRegex(ValueError, "reference"):
            self.record(authorization_reference="")

    def test_malformed_scope_count_fails_closed(self):
        from dataclasses import replace

        for invalid_count in (True, 1.0, "1", -1, None):
            with self.subTest(count=invalid_count), self.assertRaisesRegex(
                ValueError, "Invalid scope violation count"
            ):
                record_network_benchmark_provenance(
                    replace(self.result, scope_violation_count=invalid_count),
                    **self.options,
                )

    def test_scope_count_must_match_observed_evidence(self):
        from dataclasses import replace

        for invalid_result in (
            replace(self.result, scope_violation_count=0),
            replace(self.result, scope_violations=()),
            replace(self.result, scope_violations=["tcp:198.51.100.20"]),
        ):
            with self.subTest(result=invalid_result), self.assertRaisesRegex(
                ValueError, "does not match evidence"
            ):
                record_network_benchmark_provenance(
                    invalid_result, **self.options,
                )

    def test_scope_evidence_labels_must_be_unique_and_canonical(self):
        from dataclasses import replace

        invalid_labels = (
            ("tcp:198.51.100.20", "tcp:198.51.100.20"),
            ("unknown:198.51.100.20",),
            ("tcp:not-an-ip",),
            ("tcp:",),
            ("tcp:198.051.100.20",),
            ("tcp:198.51.100.20", None),
        )
        for labels in invalid_labels:
            with self.subTest(labels=labels), self.assertRaisesRegex(
                ValueError, "Scope violations"
            ):
                record_network_benchmark_provenance(
                    replace(
                        self.result,
                        scope_violations=labels,
                        scope_violation_count=len(labels),
                    ),
                    **self.options,
                )

    def test_canonical_ipv6_scope_evidence_is_supported(self):
        from dataclasses import replace

        provenance = record_network_benchmark_provenance(
            replace(
                self.result,
                scope_violations=("udp:2001:db8::10",),
                scope_violation_count=1,
            ),
            **self.options,
        )
        self.assertEqual(provenance.scope_violation_count, 1)

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
