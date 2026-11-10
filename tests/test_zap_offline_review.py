import json
import unittest

from nightrecon_red_engine.zap_offline_review import review_zap_offline_json
from nightrecon_red_engine.zap_offline_json_import import ZapOfflineImportError
from nightrecon_red_engine.tier1_offline_plan import Tier1PlanError


def fixture(site="example.org", instance="example.org", risk="2"):
    return json.dumps({"site": [{"@name": f"https://{site}",
        "alerts": [{"pluginid": "10021", "riskcode": risk,
                    "instances": [{"uri": f"https://{instance}/path"}]}]}]}).encode()


class ZapOfflineReviewTests(unittest.TestCase):
    def kwargs(self):
        return {"payload": fixture(), "targets": ("example.org",),
                "allowed_targets": ("example.org", "other.example.org"),
                "capabilities": {}, "engagement_authorized": True}

    def test_deterministic_report_and_provenance(self):
        first = review_zap_offline_json(**self.kwargs())
        self.assertEqual(first, review_zap_offline_json(**self.kwargs()))
        report = first["report"]
        self.assertEqual(report["finding_status"], "not_assessed")
        self.assertEqual(report["observation_count"], 1)
        self.assertEqual(report["observations"][0]["reported_riskcode"], "2")
        self.assertEqual(report["observations"][0]["classification"],
                         "unverified_tool_observation")
        self.assertEqual(report["observations"][0]["artifact_sha256"], report["artifact_sha256"])
        self.assertEqual(report["observations"][0]["record_index"], 0)
        self.assertEqual(len(report["report_sha256"]), 64)
        self.assertTrue(all(not step["executable"] for step in first["plan"]["steps"]))
        self.assertIn("guarded_executor_and_live_policy_required",
                      first["plan"]["steps"][1]["blockers"])
        self.assertIn("capability_not_registered", first["plan"]["steps"][1]["blockers"])

    def test_authorization_and_scope_fail_closed(self):
        for changes in ({"engagement_authorized": False},
                        {"targets": ("other.example.org",)},
                        {"allowed_targets": ("other.example.org",)},
                        {"targets": ("*.example.org",)},
                        {"targets": ("EXAMPLE.ORG",)}):
            with self.subTest(changes=changes), self.assertRaises(
                    (Tier1PlanError, ZapOfflineImportError)):
                review_zap_offline_json(**(self.kwargs() | changes))

    def test_bad_artifacts_and_scope_fail_closed(self):
        for data in (fixture(instance="evil.test"), fixture(site="sub.example.org"),
                     fixture(instance="example.org@evil.test"), fixture(risk="confirmed"),
                     b"{}", b"{"):
            with self.subTest(data=data), self.assertRaises(ZapOfflineImportError):
                review_zap_offline_json(**(self.kwargs() | {"payload": data}))

    def test_resource_limits(self):
        for changes in ({"max_bytes": 1}, {"max_records": 0},
                        {"max_records": 1, "payload": json.dumps({"site": [
                            {"@name": "https://example.org", "alerts": [
                                {"pluginid": "1", "riskcode": "2", "instances": [
                                    {"uri": "https://example.org/a"},
                                    {"uri": "https://example.org/b"}]}]}]}).encode()}):
            with self.subTest(changes=changes), self.assertRaises(ZapOfflineImportError):
                review_zap_offline_json(**(self.kwargs() | changes))


if __name__ == "__main__":
    unittest.main()
