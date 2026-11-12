"""Offline exact-target and fail-closed contract for Trivy evidence ingestion."""
import hashlib
import json
import unittest

from nightrecon_red_engine.trivy_offline_json_import import TrivyEvidenceError, import_trivy_json


def fixture(target="fixture-image@sha256:abc", vulnerabilities=None):
    return json.dumps({"SchemaVersion": 2, "Results": [
        {"Target": target, "Class": "os-pkgs", "Vulnerabilities": vulnerabilities if vulnerabilities is not None else [
            {"VulnerabilityID": "CVE-2026-0001", "PkgName": "fixture-pkg",
             "InstalledVersion": "1", "FixedVersion": "2", "Severity": "HIGH",
             "Description": "untrusted narrative"}
        ]}
    ]}).encode()


class TestTrivyOfflineImport(unittest.TestCase):
    def test_exact_target_and_digest_with_unverified_finding(self):
        payload = fixture()
        report = import_trivy_json(payload, approved_targets=("fixture-image@sha256:abc",))
        self.assertEqual(report["payload_sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(report["finding_count"], 1)
        self.assertEqual(report["observed_target_count"], 1)
        self.assertEqual(report["findings"][0]["classification"], "unverified_tool_observation")
        self.assertEqual(report["findings"][0]["reported_severity"], "HIGH")
        self.assertNotIn("Description", json.dumps(report))
        self.assertIn("not_authorization", report["authority"])

    def test_no_findings_does_not_imply_complete_coverage(self):
        report = import_trivy_json(fixture(vulnerabilities=[]),
                                   approved_targets=("fixture-image@sha256:abc", "other"))
        self.assertEqual(report["finding_count"], 0)
        self.assertEqual(report["observed_target_count"], 1)
        self.assertEqual(report["approved_target_count"], 2)

    def test_scope_and_schema_fail_closed(self):
        cases = [
            (fixture(target="other"), ("fixture-image@sha256:abc",)),
            (fixture(), ()),
            (b"", ("fixture-image@sha256:abc",)),
            (b"{", ("fixture-image@sha256:abc",)),
            (b"[]", ("fixture-image@sha256:abc",)),
            (b'{"SchemaVersion":1,"Results":[]}', ("fixture-image@sha256:abc",)),
            (b'{"SchemaVersion":2,"Results":{}}', ("fixture-image@sha256:abc",)),
            (fixture(vulnerabilities=[{"VulnerabilityID": "CVE-X"}]), ("fixture-image@sha256:abc",)),
        ]
        for payload, targets in cases:
            with self.subTest(payload=payload[:50]), self.assertRaises(TrivyEvidenceError):
                import_trivy_json(payload, approved_targets=targets)

    def test_budgets_and_invalid_scope(self):
        payload = fixture()
        with self.assertRaises(TrivyEvidenceError):
            import_trivy_json(payload, approved_targets=("fixture-image@sha256:abc",), max_bytes=2)
        with self.assertRaises(TrivyEvidenceError):
            import_trivy_json(payload, approved_targets=("fixture-image@sha256:abc",), max_findings=0)
        with self.assertRaises(TrivyEvidenceError):
            import_trivy_json(payload, approved_targets=("fixture-image@sha256:abc",), max_findings=1.5)
        with self.assertRaises(TrivyEvidenceError):
            import_trivy_json(fixture(vulnerabilities=[{"VulnerabilityID": "CVE-X", "PkgName": "p"}] * 2), approved_targets=("fixture-image@sha256:abc",), max_findings=1)
        with self.assertRaises(TrivyEvidenceError):
            import_trivy_json(payload, approved_targets=("fixture-image@sha256:abc", "fixture-image@sha256:abc"))


if __name__ == "__main__":
    unittest.main()
