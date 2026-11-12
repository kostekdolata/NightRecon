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

    def test_scoped_alert_paths_are_accepted_but_never_disclosed(self):
        base = report()
        nested = report(url="https://example.test/private/session/123")
        root = import_zap_alerts(base, approved_origins=("https://example.test",))
        scoped = import_zap_alerts(nested, approved_origins=("https://example.test",))
        self.assertEqual(scoped["unique_observation_count"], 1)
        self.assertEqual(scoped["observations"], root["observations"])
        self.assertNotIn("private", str(scoped))
        self.assertNotIn("session", str(scoped))
        self.assertNotIn("example.test", str(scoped))
        self.assertNotEqual(scoped["source_report_sha256"], root["source_report_sha256"])
        for bad in ("https://example.test/path?token=secret",
                    "https://example.test/path#fragment",
                    "https://user@example.test/path",
                    "https://example.test.evil/path",
                    "https://example.test\\\\path"):
            with self.subTest(url=bad), self.assertRaises(ZapEvidenceError):
                import_zap_alerts(report(url=bad), approved_origins=("https://example.test",))

    def test_nested_zap_site_instances_are_bounded_and_redacted(self):
        nested = {"site": [{"@name": "https://example.test", "alerts": [{
            "pluginid": "10021", "riskcode": "2", "instances": [
                {"uri": "https://example.test/private/one"},
                {"uri": "https://example.test/private/two"}]}]}]}
        payload = json.dumps(nested).encode()
        result = import_zap_alerts(payload, approved_origins=("https://example.test",))
        self.assertEqual(result["alert_count"], 2)
        self.assertEqual(result["unique_observation_count"], 1)
        self.assertEqual(result["source_report_sha256"], hashlib.sha256(payload).hexdigest())
        self.assertNotIn("private", str(result))
        self.assertNotIn("example.test", str(result))
        for bad in (
            {"site": [{"@name": "https://evil.test", "alerts": nested["site"][0]["alerts"]}]},
            {"site": [{"@name": "https://example.test", "alerts": [{
                "pluginid": "10021", "riskcode": "2", "instances": [
                    {"uri": "https://evil.test/"}]}]}]},
            {"site": [{"@name": "https://example.test", "alerts": [{
                "pluginid": "10021", "riskcode": "2", "instances": []}]}]},
            {"site": [{"@name": "https://example.test", "alerts": [{
                "pluginid": "10021", "riskcode": "2", "instances": [
                    {"uri": "https://example.test/path?secret=1"}]}]}]},
            {"site": [] , "alerts": []},
        ):
            with self.subTest(bad=bad), self.assertRaises(ZapEvidenceError):
                import_zap_alerts(json.dumps(bad).encode(),
                                  approved_origins=("https://example.test",))
        with self.assertRaises(ZapEvidenceError):
            import_zap_alerts(payload, approved_origins=("https://example.test",),
                              max_alerts=1)

    def test_out_of_scope_and_malformed_fail_closed(self):
        invalid = [report(url="https://example.test.evil"), report(url="https://evil.test"),
                   report(url="https://user@example.test"), report(url="https://example.test.evil/path"),
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
