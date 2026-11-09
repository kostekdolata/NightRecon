import unittest

from nightrecon_red_engine.offline_tool_correlation import OfflineCorrelationError
from nightrecon_red_engine.tier1_offline_plan import Tier1PlanError
from nightrecon_red_engine.tier1_offline_evidence import review_tier1_offline_evidence


def artifact(tool, host, digest):
    item = {"classification": "unverified_tool_observation",
            "name" if tool == "Amass" else "host": host}
    return {"source_tool": tool, "source_name": "fixture.json",
            "sha256": digest, "authority": "untrusted_offline_import",
            "record_count": 1, "observations": [item]}


class Tier1OfflineEvidenceTests(unittest.TestCase):
    def args(self):
        return {
            "imports": (artifact("Amass", "lab.example", "a" * 64),
                        artifact("ProjectDiscovery httpx", "lab.example", "b" * 64),
                        artifact("Greenbone/OpenVAS", "lab.example", "c" * 64)),
            "targets": ("lab.example",),
            "allowed_targets": ("lab.example", "other.example"),
            "capabilities": {},
            "engagement_authorized": True,
        }

    def test_three_tool_review_is_deterministic_provenance_preserving_and_blocked(self):
        first = review_tier1_offline_evidence(**self.args())
        self.assertEqual(first, review_tier1_offline_evidence(**self.args()))
        self.assertEqual(first["report"]["observation_count"], 3)
        self.assertEqual(first["report"]["host_count"], 1)
        self.assertEqual(first["report"]["hosts"][0]["finding_status"], "not_assessed")
        self.assertEqual({e["artifact_sha256"] for e in first["report"]["hosts"][0]["evidence"]},
                         {"a" * 64, "b" * 64, "c" * 64})
        self.assertEqual(len(first["plans"]), 3)
        self.assertTrue(all(not step["executable"] and step["status"] == "blocked"
                            and "capability_not_registered" in step["blockers"]
                            for step in first["plans"]))

    def test_scope_and_authorization_fail_closed(self):
        args = self.args()
        args["engagement_authorized"] = False
        with self.assertRaises(Tier1PlanError):
            review_tier1_offline_evidence(**args)
        args = self.args()
        args["targets"] = ("other.example",)
        with self.assertRaises(OfflineCorrelationError):
            review_tier1_offline_evidence(**args)
        args = self.args()
        args["targets"] = ("out.example",)
        with self.assertRaises(Tier1PlanError):
            review_tier1_offline_evidence(**args)

    def test_malformed_evidence_and_budget_fail_closed(self):
        args = self.args()
        args["imports"][0]["sha256"] = "invalid"
        with self.assertRaises(OfflineCorrelationError):
            review_tier1_offline_evidence(**args)
        args = self.args()
        args["max_observations"] = 2
        with self.assertRaises(OfflineCorrelationError):
            review_tier1_offline_evidence(**args)
        args = self.args()
        args["imports"] = (artifact("Metasploit Framework", "lab.example", "a" * 64),)
        with self.assertRaises(OfflineCorrelationError):
            review_tier1_offline_evidence(**args)


if __name__ == "__main__":
    unittest.main()
