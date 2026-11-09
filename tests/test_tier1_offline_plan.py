import unittest

from nightrecon_red_engine.tier1_offline_plan import Tier1PlanError, plan_tier1


class Tier1PlanTests(unittest.TestCase):
    def kwargs(self):
        return dict(objective="web_findings", targets=("lab.example",),
                    allowed_targets=("lab.example",),
                    capabilities={"Nuclei": {"available": True, "platform_supported": True,
                                             "prerequisites_met": True}},
                    engagement_authorized=True)

    def test_explainable_selection_never_executable(self):
        result = plan_tier1(**self.kwargs())
        self.assertEqual([s["tool"] for s in result["steps"]], ["Nuclei", "OWASP ZAP"])
        self.assertTrue(all(not s["executable"] for s in result["steps"]))
        self.assertTrue(all(s["status"] == "blocked" for s in result["steps"]))
        self.assertIn("capability_not_registered", result["steps"][1]["blockers"])
        self.assertTrue(all(s["requires_separate_intrusive_approval"] for s in result["steps"]))

    def test_scope_and_authorization_fail_closed(self):
        for changes in ({"targets": ("sub.lab.example",)},
                        {"allowed_targets": ("other.example",)},
                        {"targets": ("*.lab.example",)},
                        {"engagement_authorized": False},
                        {"engagement_authorized": 1},
                        {"targets": ()}):
            with self.subTest(changes=changes), self.assertRaises(Tier1PlanError):
                plan_tier1(**(self.kwargs() | changes))

    def test_unregistered_and_bad_capability_fail_closed(self):
        for value in ({"Unknown": {"available": True}},
                      {"Nuclei": {"available": 1, "platform_supported": True,
                                  "prerequisites_met": True}},
                      {"Nuclei": {"available": True}}):
            with self.subTest(value=value), self.assertRaises(Tier1PlanError):
                plan_tier1(**(self.kwargs() | {"capabilities": value}))

    def test_offline_packet_review_still_non_executable(self):
        k = self.kwargs() | {"objective": "offline_packet_review",
                             "capabilities": {"Wireshark/TShark": {
                                 "available": True, "platform_supported": True,
                                 "prerequisites_met": True}}}
        step = plan_tier1(**k)["steps"][0]
        self.assertEqual(step["status"], "offline_plan_only")
        self.assertFalse(step["executable"])


if __name__ == "__main__":
    unittest.main()
