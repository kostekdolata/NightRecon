import json
import unittest

from nightrecon_red_engine.semgrep_sarif_import import (
    SemgrepEvidenceError, import_semgrep_sarif,
)


def sarif(results=None, driver="Semgrep"):
    return json.dumps({"version": "2.1.0", "runs": [
        {"tool": {"driver": {"name": driver}}, "results": results or []}
    ]}).encode()


class TestSemgrepSarifImport(unittest.TestCase):
    def test_valid_evidence_is_unverified_and_digest_bound(self):
        result = import_semgrep_sarif(sarif([{
            "ruleId": "python.security.test", "level": "warning",
            "message": {"text": "Potential issue"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/a.py"}}}],
        }]), source_name="fixture.sarif")
        self.assertEqual(result["finding_count"], 1)
        self.assertEqual(result["authority"], "untrusted_offline_import")
        self.assertEqual(result["findings"][0]["classification"], "unverified_tool_observation")
        self.assertEqual(result["findings"][0]["artifact_uris"], ["src/a.py"])
        self.assertEqual(len(result["sha256"]), 64)

    def test_empty_valid_results(self):
        self.assertEqual(import_semgrep_sarif(sarif(), source_name="fixture")["finding_count"], 0)

    def test_fail_closed_inputs(self):
        invalid = [
            b"", b"{", b"[]", b'{"version":"2.1.0","runs":{}}',
            sarif(driver="NotSemgrep"),
            sarif([{"message": {"text": "no rule"}}]),
            sarif([{"ruleId": "x", "locations": "invalid"}]),
            sarif([{"ruleId": "x", "message": {"text": 123}}]),
        ]
        for payload in invalid:
            with self.subTest(payload=payload[:60]):
                with self.assertRaises(SemgrepEvidenceError):
                    import_semgrep_sarif(payload, source_name="fixture")

    def test_result_budget(self):
        with self.assertRaises(SemgrepEvidenceError):
            import_semgrep_sarif(sarif([{"ruleId": "x"}] * 2),
                                 source_name="fixture", max_results=1)

    def test_payload_budget(self):
        with self.assertRaises(SemgrepEvidenceError):
            import_semgrep_sarif(sarif(), source_name="fixture", max_bytes=3)


if __name__ == "__main__":
    unittest.main()
