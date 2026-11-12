"""Synthetic offline review tests; no external tools, networks or credentials."""
import json
import unittest

from nightrecon_red_engine.trivy_offline_json_import import import_trivy_json
from nightrecon_red_engine.semgrep_sarif_import import import_semgrep_sarif
from nightrecon_red_engine.static_evidence_operator_review import StaticReviewError, build_static_review


def inputs():
    trivy = import_trivy_json(json.dumps({
        "SchemaVersion": 2, "Results": [{"Target": "image@sha256:abc", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2026-1234", "PkgName": "libexample"},
            {"VulnerabilityID": "CVE-2026-1234", "PkgName": "libexample"},
        ]}]}).encode(), approved_targets=("image@sha256:abc",))
    semgrep = import_semgrep_sarif(json.dumps({
        "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Semgrep"}},
        "results": [{"ruleId": "example.rule", "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": "src/app.py"}}}]}]}]
    }).encode(), source_name="approved-local-source")
    return trivy, semgrep


class StaticReviewTests(unittest.TestCase):
    def test_deterministic_dedup_and_no_cross_tool_claim(self):
        t, s = inputs()
        report = build_static_review(t, s)
        self.assertEqual(report, build_static_review(t, s))
        self.assertEqual(report["observation_count"], 3)
        self.assertEqual(report["review_group_count"], 2)
        self.assertEqual(sorted(x["observation_count"] for x in report["review_groups"]), [1, 2])
        self.assertEqual(report["cross_tool_correlations"], [])
        self.assertTrue(all(x["exploitability"] == "not_established" for x in report["review_groups"]))
        self.assertEqual(report["authority"], "review_only_not_authorization")

    def test_missing_or_tampered_provenance_fails_closed(self):
        t, s = inputs()
        t["payload_sha256"] = "not-a-digest"
        with self.assertRaises(StaticReviewError):
            build_static_review(t, s)
        t, s = inputs()
        s["authority"] = "authorized"
        with self.assertRaises(StaticReviewError):
            build_static_review(t, s)

    def test_budgets_and_invalid_identity_fail_closed(self):
        t, s = inputs()
        with self.assertRaises(StaticReviewError):
            build_static_review(t, s, max_findings=2)
        t["findings"][0]["target"] = None
        with self.assertRaises(StaticReviewError):
            build_static_review(t, s)
        t, s = inputs()
        s["findings"][0]["artifact_uris"] = [42]
        with self.assertRaises(StaticReviewError):
            build_static_review(t, s)


if __name__ == "__main__":
    unittest.main()
