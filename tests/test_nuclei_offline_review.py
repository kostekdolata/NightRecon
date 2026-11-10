import json
import unittest

from nightrecon_red_engine.nuclei_offline_review import review_nuclei_offline_jsonl
from nightrecon_red_engine.nuclei_offline_jsonl_import import NucleiOfflineImportError
from nightrecon_red_engine.tier1_offline_plan import Tier1PlanError


def record(host="example.org", severity="high"):
    return json.dumps({"template-id": "test-template", "matched-at": f"https://{host}/",
                       "info": {"severity": severity}}).encode()


class NucleiOfflineReviewTests(unittest.TestCase):
    def kwargs(self):
        return {"payload": record(), "targets": ("example.org",),
                "allowed_targets": ("example.org", "other.example.org"),
                "capabilities": {}, "engagement_authorized": True}

    def test_report_deterministic_provenance_and_no_verdict(self):
        first = review_nuclei_offline_jsonl(**self.kwargs())
        self.assertEqual(first, review_nuclei_offline_jsonl(**self.kwargs()))
        self.assertEqual(first["report"]["observation_count"], 1)
        self.assertEqual(first["report"]["finding_status"], "not_assessed")
        self.assertEqual(first["report"]["observations"][0]["record_index"], 0)
        self.assertEqual(first["report"]["observations"][0]["reported_severity"], "high")
        self.assertEqual(len(first["report"]["report_sha256"]), 64)
        self.assertEqual(first["report"]["observations"][0]["artifact_sha256"],
                         first["report"]["artifact_sha256"])
        self.assertTrue(all(not step["executable"] for step in first["plan"]["steps"]))
        self.assertIn("guarded_executor_and_live_policy_required",
                      first["plan"]["steps"][0]["blockers"])

    def test_authorization_and_exact_scope_fail_closed(self):
        for change in ({"engagement_authorized": False},
                       {"targets": ("other.example.org",)},
                       {"allowed_targets": ("other.example.org",)},
                       {"targets": ("*.example.org",)},
                       {"targets": ("EXAMPLE.ORG",)}):
            with self.subTest(change=change), self.assertRaises(
                    (Tier1PlanError, NucleiOfflineImportError)):
                review_nuclei_offline_jsonl(**(self.kwargs() | change))

    def test_imported_scope_and_malformed_data_fail_closed(self):
        for payload in (record("sub.example.org"), record("evil.test"),
                        b"{}", b"{", record(severity="confirmed_exploitable")):
            with self.subTest(payload=payload), self.assertRaises(NucleiOfflineImportError):
                review_nuclei_offline_jsonl(**(self.kwargs() | {"payload": payload}))

    def test_budgets_and_missing_capabilities(self):
        result = review_nuclei_offline_jsonl(**self.kwargs())
        self.assertIn("capability_not_registered", result["plan"]["steps"][0]["blockers"])
        for change in ({"max_bytes": 1}, {"max_records": 0},
                       {"payload": record() + b"\n" + record(), "max_records": 1}):
            with self.subTest(change=change), self.assertRaises(NucleiOfflineImportError):
                review_nuclei_offline_jsonl(**(self.kwargs() | change))


if __name__ == "__main__":
    unittest.main()
