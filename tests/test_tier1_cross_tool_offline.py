import copy
import json
import unittest

from nightrecon_red_engine.nuclei_offline_review import review_nuclei_offline_jsonl
from nightrecon_red_engine.zap_offline_review import review_zap_offline_json
from nightrecon_red_engine.tier1_cross_tool_offline import (
    CrossToolReviewError, correlate_nuclei_zap_offline,
)
from nightrecon_red_engine.tier1_offline_plan import Tier1PlanError


class CrossToolOfflineTests(unittest.TestCase):
    def kwargs(self):
        scope = dict(targets=("example.org",), allowed_targets=("example.org",),
                     capabilities={}, engagement_authorized=True)
        nuclei = (json.dumps({"template-id": "sample-template", "host": "https://example.org/a",
                              "info": {"severity": "low"}}) + "\n").encode()
        zap = json.dumps({"site": [{"@name": "https://example.org",
            "alerts": [{"pluginid": "10021", "riskcode": "2",
                        "instances": [{"uri": "https://example.org/b"}]}]}]}).encode()
        return dict(nuclei_workflow=review_nuclei_offline_jsonl(payload=nuclei, **scope),
                    zap_workflow=review_zap_offline_json(payload=zap, **scope), **scope)

    def test_deterministic_cooccurrence_is_not_vulnerability_agreement(self):
        kwargs = self.kwargs()
        first = correlate_nuclei_zap_offline(**kwargs)
        self.assertEqual(first, correlate_nuclei_zap_offline(**kwargs))
        report = first["report"]
        self.assertEqual(report["finding_status"], "not_assessed")
        self.assertEqual(len(report["host_groups"]), 1)
        self.assertEqual(report["host_groups"][0]["host"], "example.org")
        self.assertEqual(report["host_groups"][0]["interpretation"],
                         "co_occurrence_only_not_same_vulnerability")
        self.assertEqual(len(report["report_sha256"]), 64)
        self.assertFalse(any(step["executable"] for step in first["plan"]["steps"]))

    def test_missing_authority_and_scope_fail_closed(self):
        for change in ({"engagement_authorized": False},
                       {"targets": ("evil.test",)},
                       {"allowed_targets": ("evil.test",)},
                       {"targets": ("EXAMPLE.ORG",)},
                       {"max_records": 0}):
            with self.subTest(change=change), self.assertRaises(
                    (Tier1PlanError, CrossToolReviewError)):
                correlate_nuclei_zap_offline(**(self.kwargs() | change))

    def test_tampering_and_finding_promotion_fail_closed(self):
        for tool, key, value in (
            ("nuclei_workflow", "finding_status", "confirmed"),
            ("zap_workflow", "observation_count", 500),
            ("nuclei_workflow", "artifact_sha256", "0" * 64),
        ):
            kwargs = self.kwargs()
            kwargs[tool] = copy.deepcopy(kwargs[tool])
            kwargs[tool]["report"][key] = value
            with self.subTest(tool=tool, key=key), self.assertRaises(CrossToolReviewError):
                correlate_nuclei_zap_offline(**kwargs)

    def test_observation_scope_and_provenance_fail_closed_even_if_rehashed(self):
        from nightrecon_red_engine.tier1_cross_tool_offline import _digest
        for field, value in (("host", "evil.test"), ("record_index", -1),
                             ("classification", "confirmed_vulnerability")):
            kwargs = self.kwargs()
            workflow = copy.deepcopy(kwargs["zap_workflow"])
            workflow["report"]["observations"][0][field] = value
            report = workflow["report"]
            report["report_sha256"] = _digest({k: v for k, v in report.items()
                                                if k != "report_sha256"})
            kwargs["zap_workflow"] = workflow
            with self.subTest(field=field), self.assertRaises(CrossToolReviewError):
                correlate_nuclei_zap_offline(**kwargs)

    def test_resource_ceiling(self):
        with self.assertRaises(CrossToolReviewError):
            correlate_nuclei_zap_offline(**(self.kwargs() | {"max_records": 0}))


if __name__ == "__main__":
    unittest.main()
