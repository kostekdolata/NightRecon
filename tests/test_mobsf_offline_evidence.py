"""Synthetic, offline-only MobSF evidence contract regression tests."""
import hashlib
import json
import unittest

from nightrecon_red_engine.mobsf_offline_evidence import (
    MobSFEvidenceError, import_mobsf_static_report,
)

ARTIFACT = hashlib.sha256(b"synthetic mobile artifact").hexdigest()


def report(**overrides):
    data = {"sha256": ARTIFACT, "app_type": "apk",
            "code_analysis": {"rule-one": {"metadata": {"severity": "high"}}}}
    data.update(overrides)
    return json.dumps(data).encode()


class MobSFOfflineEvidenceTests(unittest.TestCase):
    def test_valid_report_is_redacted_and_not_authority(self):
        raw = report(code_analysis={"rule-one": {
            "metadata": {"severity": "high"}, "files": {"secret.java": "private content"}}})
        result = import_mobsf_static_report(raw, approved_artifact_sha256=ARTIFACT)
        self.assertEqual(result["observation_count"], 1)
        self.assertEqual(result["source_report_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result["authority"], "evidence_only_not_authorization")
        self.assertNotIn("private content", str(result))
        self.assertNotIn("secret.java", str(result))
        self.assertEqual(result["observations"][0]["exploitability"], "not_established")

    def test_scope_and_schema_fail_closed(self):
        cases = (report(sha256="b" * 64), report(sha256=None),
                 report(app_type="unknown"), report(code_analysis=[]),
                 report(code_analysis={"r": {"metadata": {"severity": "critical"}}}),
                 b"not json", b"[]", b"")
        for raw in cases:
            with self.subTest(raw=raw[:40]), self.assertRaises(MobSFEvidenceError):
                import_mobsf_static_report(raw, approved_artifact_sha256=ARTIFACT)
        with self.assertRaises(MobSFEvidenceError):
            import_mobsf_static_report(report(), approved_artifact_sha256="invalid")

    def test_budgets_and_missing_tool_do_not_trigger_execution(self):
        with self.assertRaises(MobSFEvidenceError):
            import_mobsf_static_report(report(), approved_artifact_sha256=ARTIFACT, max_findings=0)
        with self.assertRaises(MobSFEvidenceError):
            import_mobsf_static_report(report(), approved_artifact_sha256=ARTIFACT, max_findings=2.5)
        with self.assertRaises(MobSFEvidenceError):
            import_mobsf_static_report(report(code_analysis={
                "a": {"metadata": {"severity": "info"}},
                "b": {"metadata": {"severity": "secure"}}}),
                approved_artifact_sha256=ARTIFACT, max_findings=1)
        with self.assertRaises(MobSFEvidenceError):
            import_mobsf_static_report(b"x" * 2_000_001, approved_artifact_sha256=ARTIFACT)


if __name__ == "__main__":
    unittest.main()
