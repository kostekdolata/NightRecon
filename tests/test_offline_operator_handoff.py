"""Synthetic offline handoff contracts; no network or external tools."""
import json
import unittest

from nightrecon_red_engine.trivy_offline_json_import import import_trivy_json
from nightrecon_red_engine.semgrep_sarif_import import import_semgrep_sarif
from nightrecon_red_engine.static_evidence_operator_review import build_static_review, StaticReviewError
from nightrecon_red_engine.offline_operator_handoff import build_operator_handoff


def fixture():
    trivy = import_trivy_json(json.dumps({
        "SchemaVersion": 2, "Results": [{"Target": "private-image@sha256:abc", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2026-1234", "PkgName": "secret-package"}]}]
    }).encode(), approved_targets=("private-image@sha256:abc",))
    semgrep = import_semgrep_sarif(json.dumps({
        "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Semgrep"}},
        "results": [{"ruleId": "private-rule", "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": "private/path.py"}}}]}]}]
    }).encode(), source_name="private-repository")
    return build_static_review(trivy, semgrep)


class HandoffTests(unittest.TestCase):
    def test_redacted_deterministic_report_and_honest_unknowns(self):
        report = build_operator_handoff(fixture())
        self.assertEqual(report, build_operator_handoff(fixture()))
        self.assertEqual(report["review_required"], 2)
        self.assertEqual(report["groups_by_tool"], {"Trivy": 1, "Semgrep": 1})
        self.assertIsNone(report["confirmed_exploitable"])
        self.assertIsNone(report["retest_verified"])
        self.assertEqual(report["authority"], "report_only_not_authorization")
        encoded = json.dumps(report)
        for secret in ("private-image", "private-rule", "private/path.py", "private-repository", "secret-package"):
            self.assertNotIn(secret, encoded)

    def test_fails_closed_on_claims_and_inconsistent_counts(self):
        r = fixture()
        r["review_groups"][0]["exploitability"] = "confirmed"
        with self.assertRaises(StaticReviewError):
            build_operator_handoff(r)
        r = fixture()
        r["observation_count"] += 1
        with self.assertRaises(StaticReviewError):
            build_operator_handoff(r)
        r = fixture()
        r["cross_tool_correlations"] = [{"claim": "same asset"}]
        with self.assertRaises(StaticReviewError):
            build_operator_handoff(r)

    def test_fails_closed_on_budget_and_duplicate_identity(self):
        r = fixture()
        with self.assertRaises(StaticReviewError):
            build_operator_handoff(r, max_groups=1)
        r["review_groups"][1]["review_id"] = r["review_groups"][0]["review_id"]
        with self.assertRaises(StaticReviewError):
            build_operator_handoff(r)


if __name__ == "__main__":
    unittest.main()
