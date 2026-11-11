"""Network-free Tier 1 capability planning safety contracts."""
import unittest

from nightrecon_red_engine.tier1_capability_plan import (
    TIER1, Tier1PlanError, plan_tier1_tools,
)


def plan(**overrides):
    values = dict(engagement_id="lab-001",
                  authorized_targets=("127.0.0.1",),
                  selected_tools=("nmap", "tshark"),
                  available_tools={"nmap": True, "tshark": True},
                  platform="linux")
    values.update(overrides)
    return plan_tier1_tools(**values)


class Tier1CapabilityPlanTests(unittest.TestCase):
    def test_all_seven_slots_are_explicit_and_non_executable(self):
        result = plan(selected_tools=tuple(TIER1),
                      available_tools={tool: True for tool in TIER1},
                      intrusive_approval=True)
        self.assertEqual(result["selected_count"], 7)
        self.assertFalse(result["execution_allowed"])
        self.assertTrue(all(not item["execution_allowed"] and
                            not item["integration_verified"]
                            for item in result["decisions"]))

    def test_missing_prerequisite_and_approval_fail_closed(self):
        result = plan(available_tools={"tshark": True})
        self.assertEqual(result["decisions"][0]["selection_reason"],
                         "trusted_prerequisite_not_attested")
        self.assertEqual(result["decisions"][1]["selection_reason"],
                         "prerequisites_only_no_executor_or_authorization")
        result = plan()
        self.assertEqual(result["decisions"][0]["selection_reason"],
                         "explicit_intrusive_approval_required")

    def test_invalid_scope_and_selection_rejected(self):
        cases = (
            {"authorized_targets": ()},
            {"authorized_targets": ("127.0.0.1", "127.0.0.1")},
            {"authorized_targets": ("127.0.0.1\\nunsafe",)},
            {"selected_tools": ("nmap", "nmap")},
            {"selected_tools": ("metasploit",)},
            {"selected_tools": ()},
            {"platform": "unknown"},
            {"available_tools": {"nmap": 1}},
            {"max_tools": 0},
            {"engagement_id": "../bad"},
            {"intrusive_approval": 1},
        )
        for kwargs in cases:
            with self.subTest(kwargs=kwargs), self.assertRaises(Tier1PlanError):
                plan(**kwargs)

    def test_plan_never_infers_authority_from_target_or_tool(self):
        result = plan(authorized_targets=("example.org",),
                      intrusive_approval=True)
        self.assertFalse(result["execution_allowed"])
        self.assertIn("no target authorization", result["limitations"])


if __name__ == "__main__":
    unittest.main()
