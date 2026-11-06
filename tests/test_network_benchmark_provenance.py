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

    def test_json_export_is_deterministic_and_offline(self):
        import json
        from nightrecon_red_engine.network_benchmark_provenance import (
            export_network_benchmark_evidence_json,
        )

        first = export_network_benchmark_evidence_json(
            self.record(), self.result,
        )
        repeated = export_network_benchmark_evidence_json(
            self.record(lab_run_id="another-run"), self.result,
        )
        self.assertEqual(first, repeated)
        payload = json.loads(first)
        self.assertEqual(payload["type"], "network-benchmark-evidence-summary")
        self.assertEqual(payload["metrics"]["scope_violation_count"], 1)
        self.assertEqual(payload["authorization_effect"], "none")
        self.assertEqual(first, json.dumps(
            payload, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ))

    def test_json_export_withholds_metrics_on_tampering(self):
        import json
        from dataclasses import replace
        from nightrecon_red_engine.network_benchmark_provenance import (
            export_network_benchmark_evidence_json,
        )

        payload = json.loads(export_network_benchmark_evidence_json(
            replace(self.record(), evidence_fingerprint="0" * 64),
            self.result,
        ))
        self.assertEqual(payload["provenance_status"]["status"], "inconsistent")
        self.assertIsNone(payload["metrics"])
        self.assertIsNone(payload["provenance_status"]["evidence_fingerprint"])

    def test_canonical_report_export_digest_matches_exact_json_bytes(self):
        import hashlib
        from nightrecon_red_engine.network_benchmark_provenance import (
            export_network_benchmark_evidence_json,
            fingerprint_network_benchmark_evidence_export,
        )

        payload = export_network_benchmark_evidence_json(
            self.record(), self.result,
        )
        digest = fingerprint_network_benchmark_evidence_export(
            self.record(), self.result,
        )
        self.assertEqual(
            digest, hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(len(digest), 64)
        self.assertEqual(
            digest,
            fingerprint_network_benchmark_evidence_export(
                self.record(lab_run_id="another-run"), self.result,
            ),
        )

    def test_export_digest_changes_with_evidence_and_preserves_redaction(self):
        import json
        from dataclasses import replace
        from nightrecon_red_engine.network_benchmark_provenance import (
            export_network_benchmark_evidence_json,
            fingerprint_network_benchmark_evidence_export,
        )

        record = self.record()
        baseline = fingerprint_network_benchmark_evidence_export(
            record, self.result,
        )
        altered = fingerprint_network_benchmark_evidence_export(
            record, replace(
                self.result, scope_violations=("udp:198.51.100.20",),
            ),
        )
        self.assertNotEqual(baseline, altered)
        tampered = replace(record, evidence_fingerprint="0" * 64)
        payload = json.loads(export_network_benchmark_evidence_json(
            tampered, self.result,
        ))
        self.assertIsNone(payload["metrics"])
        self.assertIsNone(payload["provenance_status"]["evidence_fingerprint"])
        self.assertEqual(
            fingerprint_network_benchmark_evidence_export(
                tampered, self.result,
            ),
            fingerprint_network_benchmark_evidence_export(
                replace(record, evidence_fingerprint="1" * 64), self.result,
            ),
        )

    def test_canonical_export_digest_verifier_round_trip_and_tampering(self):
        from nightrecon_red_engine.network_benchmark_provenance import (
            export_network_benchmark_evidence_json,
            fingerprint_network_benchmark_evidence_export,
            verify_network_benchmark_evidence_export_digest,
        )

        payload = export_network_benchmark_evidence_json(
            self.record(), self.result,
        )
        digest = fingerprint_network_benchmark_evidence_export(
            self.record(), self.result,
        )
        self.assertTrue(verify_network_benchmark_evidence_export_digest(
            payload, digest,
        ))
        self.assertTrue(verify_network_benchmark_evidence_export_digest(
            payload, digest.upper(),
        ))
        self.assertFalse(verify_network_benchmark_evidence_export_digest(
            payload, "0" * 64,
        ))
        self.assertFalse(verify_network_benchmark_evidence_export_digest(
            payload + " ", digest,
        ))
        self.assertFalse(verify_network_benchmark_evidence_export_digest(
            payload, "invalid",
        ))

    def test_export_verifier_rejects_noncanonical_and_untrusted_payloads(self):
        import hashlib
        import json
        from nightrecon_red_engine.network_benchmark_provenance import (
            export_network_benchmark_evidence_json,
            verify_network_benchmark_evidence_export_digest,
        )

        valid = export_network_benchmark_evidence_json(
            self.record(), self.result,
        )
        payloads = (
            '{"type":"unrelated"}',
            '{"type":"network-benchmark-evidence-summary","extra":NaN}',
            '{"type":"network-benchmark-evidence-summary","type":"network-benchmark-evidence-summary"}',
            json.dumps(json.loads(valid), indent=2, sort_keys=True),
            "not json",
            "a" * (1_048_576 + 1),
            "\\ud800",
        )
        for payload in payloads:
            with self.subTest(payload=payload[:30]):
                # Even a digest matching invalid input must not validate it.
                digest = hashlib.sha256(
                    payload.encode("utf-8", errors="surrogatepass")
                ).hexdigest()
                self.assertFalse(verify_network_benchmark_evidence_export_digest(
                    payload, digest,
                ))
        self.assertFalse(verify_network_benchmark_evidence_export_digest(
            valid, None,
        ))
        with self.assertRaises(TypeError):
            verify_network_benchmark_evidence_export_digest({}, "a" * 64)

    def test_digest_verifier_does_not_unredact_inconsistent_evidence(self):
        import json
        from dataclasses import replace
        from nightrecon_red_engine.network_benchmark_provenance import (
            export_network_benchmark_evidence_json,
            fingerprint_network_benchmark_evidence_export,
            verify_network_benchmark_evidence_export_digest,
        )

        tampered = replace(self.record(), evidence_fingerprint="0" * 64)
        payload = export_network_benchmark_evidence_json(
            tampered, self.result,
        )
        digest = fingerprint_network_benchmark_evidence_export(
            tampered, self.result,
        )
        self.assertTrue(verify_network_benchmark_evidence_export_digest(
            payload, digest,
        ))
        parsed = json.loads(payload)
        self.assertIsNone(parsed["metrics"])
        self.assertEqual(parsed["provenance_status"]["status"], "inconsistent")

    def test_offline_export_intake_accepts_matching_and_redacted_reports(self):
        from dataclasses import replace
        from nightrecon_red_engine.network_benchmark_provenance import (
            export_network_benchmark_evidence_json,
            fingerprint_network_benchmark_evidence_export,
            inspect_network_benchmark_evidence_export,
        )

        for provenance, expected in (
            (self.record(), "scope_violations_observed"),
            (replace(self.record(), evidence_fingerprint="0" * 64), "inconsistent"),
        ):
            with self.subTest(expected=expected):
                payload = export_network_benchmark_evidence_json(
                    provenance, self.result,
                )
                digest = fingerprint_network_benchmark_evidence_export(
                    provenance, self.result,
                )
                intake = inspect_network_benchmark_evidence_export(
                    payload, digest,
                )
                self.assertTrue(intake["accepted"])
                self.assertEqual(intake["status"], expected)
                self.assertEqual(intake["authorization_effect"], "none")
                if expected == "inconsistent":
                    self.assertIsNone(intake["metrics"])
                else:
                    self.assertEqual(intake["metrics"]["scope_violation_count"], 1)

    def test_offline_export_intake_rejects_forged_safety_states(self):
        import hashlib
        import json
        from nightrecon_red_engine.network_benchmark_provenance import (
            export_network_benchmark_evidence_json,
            inspect_network_benchmark_evidence_export,
        )

        payload = export_network_benchmark_evidence_json(
            self.record(), self.result,
        )
        valid = json.loads(payload)
        forged = []
        for changes in (
            {"status": "consistent_unverified"},
            {"status": "inconsistent"},
            {"scope_violation_count": 0},
            {"authorization_effect": "approved"},
            {"evidence_fingerprint": None},
        ):
            altered = json.loads(payload)
            altered["provenance_status"].update(changes)
            forged.append(altered)
        altered = json.loads(payload)
        altered["authorization_effect"] = "approved"
        forged.append(altered)
        altered = json.loads(payload)
        altered["metrics"] = None
        forged.append(altered)
        altered = json.loads(payload)
        altered["schema"] = 999
        forged.append(altered)
        for report in forged:
            encoded = json.dumps(
                report, sort_keys=True, separators=(",", ":"), allow_nan=False,
            )
            digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
            with self.subTest(report=report):
                self.assertFalse(inspect_network_benchmark_evidence_export(
                    encoded, digest,
                )["accepted"])
        self.assertFalse(inspect_network_benchmark_evidence_export(
            payload, "0" * 64,
        )["accepted"])

    def test_offline_export_intake_rejects_invalid_metric_schema(self):
        import hashlib
        import json
        from nightrecon_red_engine.network_benchmark_provenance import (
            export_network_benchmark_evidence_json,
            inspect_network_benchmark_evidence_export,
        )

        baseline = json.loads(export_network_benchmark_evidence_json(
            self.record(), self.result,
        ))
        for value in (True, -1, 1.5, "1", None):
            altered = json.loads(json.dumps(baseline))
            altered["metrics"]["expected_tcp_open"] = value
            encoded = json.dumps(
                altered, sort_keys=True, separators=(",", ":"), allow_nan=False,
            )
            digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
            with self.subTest(value=value):
                self.assertFalse(inspect_network_benchmark_evidence_export(
                    encoded, digest,
                )["accepted"])
        for mutation in ("missing", "extra"):
            altered = json.loads(json.dumps(baseline))
            if mutation == "missing":
                del altered["metrics"]["matched_tcp_open"]
            else:
                altered["metrics"]["unverified_authorization"] = 1
            encoded = json.dumps(
                altered, sort_keys=True, separators=(",", ":"), allow_nan=False,
            )
            digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
            with self.subTest(mutation=mutation):
                self.assertFalse(inspect_network_benchmark_evidence_export(
                    encoded, digest,
                )["accepted"])

    def test_offline_export_intake_rejects_unknown_envelope_fields(self):
        import hashlib
        import json
        from nightrecon_red_engine.network_benchmark_provenance import (
            export_network_benchmark_evidence_json,
            inspect_network_benchmark_evidence_export,
        )

        original = json.loads(export_network_benchmark_evidence_json(
            self.record(), self.result,
        ))
        for mutation in ("extra_top", "missing_top", "extra_status",
                         "missing_status", "wrong_type", "bool_schema",
                         "bool_status_schema", "bad_interpretation"):
            altered = json.loads(json.dumps(original))
            status = altered["provenance_status"]
            if mutation == "extra_top":
                altered["authorized"] = True
            elif mutation == "missing_top":
                del altered["interpretation"]
            elif mutation == "extra_status":
                status["approved"] = True
            elif mutation == "missing_status":
                del status["interpretation"]
            elif mutation == "wrong_type":
                altered["type"] = "network-benchmark-authorization"
            elif mutation == "bool_schema":
                altered["schema"] = True
            elif mutation == "bool_status_schema":
                status["schema"] = True
            else:
                altered["interpretation"] = None
            encoded = json.dumps(
                altered, sort_keys=True, separators=(",", ":"), allow_nan=False,
            )
            digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
            with self.subTest(mutation=mutation):
                self.assertFalse(inspect_network_benchmark_evidence_export(
                    encoded, digest,
                )["accepted"])

    def test_offline_export_intake_clean_is_not_verified_authorization(self):
        from nightrecon_red_engine.network_benchmark_provenance import (
            export_network_benchmark_evidence_json,
            fingerprint_network_benchmark_evidence_export,
            inspect_network_benchmark_evidence_export,
        )

        clean = benchmark_network_observations(
            NetworkBenchmarkExpectation(authorized_addresses=("192.0.2.10",)),
        )
        record = record_network_benchmark_provenance(clean, **self.options)
        intake = inspect_network_benchmark_evidence_export(
            export_network_benchmark_evidence_json(record, clean),
            fingerprint_network_benchmark_evidence_export(record, clean),
        )
        self.assertTrue(intake["accepted"])
        self.assertEqual(intake["status"], "consistent_unverified")
        self.assertEqual(intake["authorization_effect"], "none")

    def test_offline_batch_intake_preserves_order_and_isolates_rejections(self):
        from dataclasses import replace
        from nightrecon_red_engine.network_benchmark_provenance import (
            export_network_benchmark_evidence_json,
            fingerprint_network_benchmark_evidence_export,
            inspect_network_benchmark_evidence_batch,
        )

        record = self.record()
        payload = export_network_benchmark_evidence_json(record, self.result)
        digest = fingerprint_network_benchmark_evidence_export(record, self.result)
        altered = replace(record, evidence_fingerprint="0" * 64)
        redacted = export_network_benchmark_evidence_json(altered, self.result)
        redacted_digest = fingerprint_network_benchmark_evidence_export(
            altered, self.result,
        )
        batch = inspect_network_benchmark_evidence_batch([
            (payload, digest),
            (payload, "0" * 64),
            (redacted, redacted_digest),
        ])
        self.assertFalse(batch["accepted"])
        self.assertEqual(batch["accepted_count"], 2)
        self.assertEqual(batch["rejected_count"], 1)
        self.assertEqual(batch["status_counts"], {
            "consistent_unverified": 0,
            "scope_violations_observed": 1,
            "inconsistent": 1,
            "rejected": 1,
        })
        self.assertEqual(sum(batch["status_counts"].values()), len(batch["entries"]))
        self.assertEqual(
            [item["status"] for item in batch["entries"]],
            ["scope_violations_observed", "rejected", "inconsistent"],
        )
        self.assertIsNone(batch["entries"][1]["metrics"])
        self.assertIsNone(batch["entries"][2]["metrics"])
        self.assertEqual(batch["authorization_effect"], "none")

    def test_offline_batch_status_counts_clean_and_rejected_entries(self):
        from nightrecon_red_engine.network_benchmark_provenance import (
            export_network_benchmark_evidence_json,
            fingerprint_network_benchmark_evidence_export,
            inspect_network_benchmark_evidence_batch,
        )

        clean = benchmark_network_observations(
            NetworkBenchmarkExpectation(authorized_addresses=("192.0.2.10",)),
        )
        record = record_network_benchmark_provenance(clean, **self.options)
        payload = export_network_benchmark_evidence_json(record, clean)
        digest = fingerprint_network_benchmark_evidence_export(record, clean)
        batch = inspect_network_benchmark_evidence_batch([
            (payload, digest), (payload, "0" * 64),
        ])
        self.assertEqual(batch["status_counts"], {
            "consistent_unverified": 1,
            "scope_violations_observed": 0,
            "inconsistent": 0,
            "rejected": 1,
        })
        self.assertEqual(batch["accepted_count"], 1)
        self.assertEqual(batch["rejected_count"], 1)
        self.assertFalse(batch["accepted"])
        self.assertIsNone(batch["entries"][1]["metrics"])
        self.assertEqual(batch["authorization_effect"], "none")

    def test_batch_review_flag_identifies_scope_and_rejected_evidence(self):
        from dataclasses import replace
        from nightrecon_red_engine.network_benchmark_provenance import (
            export_network_benchmark_evidence_json,
            fingerprint_network_benchmark_evidence_export,
            inspect_network_benchmark_evidence_batch,
        )

        clean = benchmark_network_observations(
            NetworkBenchmarkExpectation(authorized_addresses=("192.0.2.10",)),
        )
        clean_record = record_network_benchmark_provenance(clean, **self.options)
        clean_entry = (
            export_network_benchmark_evidence_json(clean_record, clean),
            fingerprint_network_benchmark_evidence_export(clean_record, clean),
        )
        scope_record = self.record()
        scope_entry = (
            export_network_benchmark_evidence_json(scope_record, self.result),
            fingerprint_network_benchmark_evidence_export(scope_record, self.result),
        )
        tampered = replace(scope_record, evidence_fingerprint="0" * 64)
        inconsistent_entry = (
            export_network_benchmark_evidence_json(tampered, self.result),
            fingerprint_network_benchmark_evidence_export(tampered, self.result),
        )
        for entries, expected in (
            ([clean_entry], False),
            ([scope_entry], True),
            ([inconsistent_entry], True),
            ([clean_entry, (clean_entry[0], "0" * 64)], True),
            ([], False),
        ):
            with self.subTest(entries=len(entries), expected=expected):
                batch = inspect_network_benchmark_evidence_batch(entries)
                self.assertIs(batch["requires_evidence_review"], expected)
                self.assertEqual(batch["authorization_effect"], "none")
        self.assertTrue(
            inspect_network_benchmark_evidence_batch([scope_entry])["accepted"]
        )

    def test_batch_review_reasons_are_deterministic_and_non_authorizing(self):
        from dataclasses import replace
        from nightrecon_red_engine.network_benchmark_provenance import (
            export_network_benchmark_evidence_json,
            fingerprint_network_benchmark_evidence_export,
            inspect_network_benchmark_evidence_batch,
        )

        clean = benchmark_network_observations(
            NetworkBenchmarkExpectation(authorized_addresses=("192.0.2.10",)),
        )
        clean_record = record_network_benchmark_provenance(clean, **self.options)
        def entry(record, result):
            return (
                export_network_benchmark_evidence_json(record, result),
                fingerprint_network_benchmark_evidence_export(record, result),
            )

        clean_entry = entry(clean_record, clean)
        scope_entry = entry(self.record(), self.result)
        inconsistent_entry = entry(
            replace(self.record(), evidence_fingerprint="0" * 64),
            self.result,
        )
        rejected_entry = (clean_entry[0], "0" * 64)
        cases = (
            ([], []),
            ([clean_entry], []),
            ([scope_entry], ["scope_violations_observed"]),
            ([inconsistent_entry], ["inconsistent"]),
            ([rejected_entry], ["rejected"]),
            ([rejected_entry, inconsistent_entry, scope_entry, clean_entry],
             ["scope_violations_observed", "inconsistent", "rejected"]),
            ([scope_entry, scope_entry], ["scope_violations_observed"]),
        )
        for exports, reasons in cases:
            with self.subTest(reasons=reasons):
                batch = inspect_network_benchmark_evidence_batch(exports)
                self.assertEqual(batch["evidence_review_reasons"], reasons)
                self.assertEqual(batch["requires_evidence_review"], bool(reasons))
                self.assertEqual(batch["authorization_effect"], "none")
                self.assertEqual(
                    sum(batch["status_counts"].values()), len(exports),
                )
    def test_offline_batch_intake_rejects_malformed_or_unbounded_inputs(self):
        from nightrecon_red_engine.network_benchmark_provenance import (
            inspect_network_benchmark_evidence_batch,
        )

        empty = inspect_network_benchmark_evidence_batch([])
        self.assertFalse(empty["accepted"])
        self.assertEqual(empty["accepted_count"], 0)
        self.assertEqual(empty["rejected_count"], 0)
        self.assertEqual(empty["status_counts"], {
            "consistent_unverified": 0,
            "scope_violations_observed": 0,
            "inconsistent": 0,
            "rejected": 0,
        })
        self.assertEqual(empty["authorization_effect"], "none")
        self.assertEqual(empty["entries"], [])
        for bad in (None, (), [{}], [["json", "a" * 64]],
                    [("json",)], [(None, "a" * 64)],
                    [("json", None)], [("json", "a" * 64)] * 33):
            with self.subTest(bad=str(bad)[:50]), self.assertRaises(ValueError):
                inspect_network_benchmark_evidence_batch(bad)

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
