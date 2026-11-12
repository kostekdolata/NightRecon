"""Synthetic network-free OWASP ZAP offline evidence tests."""
import hashlib
import json
import unittest

from nightrecon_red_engine.zap_offline_evidence import (
    ZapEvidenceError, import_zap_alerts,
)


def report(url="https://example.test", plugin="10021", risk=2):
    return json.dumps({"alerts": [{"url": url, "pluginId": plugin,
                                   "riskcode": risk}]}).encode()


class ZapOfflineEvidenceTests(unittest.TestCase):
    def test_valid_redacted_and_deterministic(self):
        payload = report()
        result = import_zap_alerts(payload, approved_origins=("https://example.test",))
        self.assertEqual(result["source_report_sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(result["unique_observation_count"], 1)
        self.assertEqual(result["authority"], "evidence_only_not_authorization")
        self.assertEqual(result["observations"][0]["exploitability"], "not_established")
        self.assertNotIn("example.test", str(result))
        self.assertEqual(result, import_zap_alerts(payload, approved_origins=("https://example.test",)))

    def test_out_of_scope_and_malformed_fail_closed(self):
        invalid = [report(url="https://example.test.evil"), report(url="https://evil.test"),
                   report(url="https://user@example.test"), report(url="https://example.test/path"),
                   report(plugin="bad"), report(risk=4), report(risk=True),
                   b'{"alerts":{}}', b'{"alerts":[null]}', b'not-json']
        for payload in invalid:
            with self.subTest(payload=payload), self.assertRaises(ZapEvidenceError):
                import_zap_alerts(payload, approved_origins=("https://example.test",))

    def test_budget_and_missing_authority(self):
        for origins, budget in [((), 1), (("https://example.test",), 0),
                                (("https://example.test",), True)]:
            with self.assertRaises(ZapEvidenceError):
                import_zap_alerts(report(), approved_origins=origins, max_alerts=budget)
        with self.assertRaises(ZapEvidenceError):
            import_zap_alerts(report() * 100000, approved_origins=("https://example.test",))
