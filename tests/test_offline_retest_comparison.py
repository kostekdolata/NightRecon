import copy
import unittest

from nightrecon_red_engine.offline_tool_correlation import OfflineCorrelationError
from nightrecon_red_engine.tier1_offline_evidence import review_tier1_offline_evidence
from nightrecon_red_engine.offline_retest_comparison import compare_offline_retests


def review(tools):
    imports = tuple({
        "source_tool": tool, "source_name": "synthetic.json",
        "sha256": chr(97 + i) * 64, "authority": "untrusted_offline_import",
        "record_count": 1, "observations": [{
            "classification": "unverified_tool_observation",
            "name" if tool == "Amass" else "host": "lab.example",
        }],
    } for i, tool in enumerate(tools))
    return review_tier1_offline_evidence(
        imports=imports, targets=("lab.example",),
        allowed_targets=("lab.example",), capabilities={},
        engagement_authorized=True)


class OfflineRetestComparisonTests(unittest.TestCase):
    def test_changed_and_persisting_observations_are_not_remediation_verdicts(self):
        before = review(("Amass", "ProjectDiscovery httpx"))
        after = review(("Amass", "Greenbone/OpenVAS"))
        result = compare_offline_retests(before, after, allowed_hosts=("lab.example",))
        self.assertEqual(result, compare_offline_retests(before, after, allowed_hosts=("lab.example",)))
        self.assertEqual([r["source_tool"] for r in result["persisting"]], ["Amass"])
        self.assertEqual([r["source_tool"] for r in result["no_longer_observed"]], ["ProjectDiscovery httpx"])
        self.assertEqual([r["source_tool"] for r in result["newly_observed"]], ["Greenbone/OpenVAS"])
        self.assertIn("do not prove remediation", result["limitations"])
        self.assertEqual(len(result["comparison_sha256"]), 64)

    def test_scope_and_tampering_fail_closed(self):
        before = review(("Amass",))
        after = copy.deepcopy(before)
        with self.assertRaises(OfflineCorrelationError):
            compare_offline_retests(before, after, allowed_hosts=("example",))
        after["report"]["hosts"][0]["finding_status"] = "confirmed"
        with self.assertRaises(OfflineCorrelationError):
            compare_offline_retests(before, after, allowed_hosts=("lab.example",))

    def test_budget_and_invalid_envelope_fail_closed(self):
        before = review(("Amass",))
        after = review(("Amass",))
        with self.assertRaises(OfflineCorrelationError):
            compare_offline_retests(before, after, allowed_hosts=("lab.example",),
                                    max_observations=0)
        with self.assertRaises(OfflineCorrelationError):
            compare_offline_retests(before, after, allowed_hosts=("lab.example",),
                                    max_observations=0)
        after["authority"] = "execution_authorized"
        with self.assertRaises(OfflineCorrelationError):
            compare_offline_retests(before, after, allowed_hosts=("lab.example",))


if __name__ == "__main__":
    unittest.main()
