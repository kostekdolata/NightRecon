import json
import unittest

from nightrecon_red_engine.zap_offline_json_import import (
    ZapOfflineImportError, import_zap_json,
)


def payload(site="example.org", instance="example.org", risk="2"):
    return json.dumps({"site": [{"@name": f"https://{site}",
        "alerts": [{"pluginid": "10021", "riskcode": risk,
                    "instances": [{"uri": f"https://{instance}/path"}]}]}]}).encode()


class ZapOfflineImportTests(unittest.TestCase):
    def call(self, **changes):
        args = {"payload": payload(), "allowed_hosts": ("example.org",)}
        args.update(changes)
        return import_zap_json(**args)

    def test_deterministic_provenance_unverified(self):
        first = self.call()
        self.assertEqual(first, self.call())
        self.assertEqual(first["record_count"], 1)
        self.assertEqual(first["observations"][0]["record_index"], 0)
        self.assertEqual(first["observations"][0]["reported_riskcode"], "2")
        self.assertEqual(first["observations"][0]["classification"],
                         "unverified_tool_observation")
        self.assertEqual(len(first["sha256"]), 64)
        self.assertIn("unverified", first["limitations"])

    def test_scope_and_credentials_fail_closed(self):
        for data in (payload(site="evil.test"),
                     payload(instance="sub.example.org"),
                     payload(site="example.org@evil.test"),
                     payload(instance="example.org@evil.test"),
                     payload(instance="EXAMPLE.ORG"),
                     payload(instance="example.org#fragment")):
            with self.subTest(data=data), self.assertRaises(ZapOfflineImportError):
                self.call(payload=data)

    def test_invalid_and_over_budget(self):
        for data in (b"{}", b"{", b"[]", b'{"site":{}}',
                     payload(risk="confirmed"), b'{"site":[null]}'):
            with self.subTest(data=data), self.assertRaises(ZapOfflineImportError):
                self.call(payload=data)
        for changes in ({"max_bytes": 1}, {"max_records": 0},
                        {"allowed_hosts": ("other.test",)},
                        {"allowed_hosts": ("example.org", "example.org")},
                        {"max_records": 1, "payload": json.dumps({"site": [
                            {"@name": "https://example.org", "alerts": [
                                {"pluginid": "1", "riskcode": "2",
                                 "instances": [{"uri": "https://example.org/a"},
                                               {"uri": "https://example.org/b"}]}]}]}).encode()}):
            with self.subTest(changes=changes), self.assertRaises(ZapOfflineImportError):
                self.call(**changes)


if __name__ == "__main__":
    unittest.main()
