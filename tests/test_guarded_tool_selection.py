"""Offline selection contract tests; no external tools or targets."""
import unittest

from nightrecon_red_engine.guarded_tool_selection import (
    TOOLS, Capability, Engagement, plan_tools,
)


class GuardedToolSelectionTests(unittest.TestCase):
    def setUp(self):
        self.engagement = Engagement(
            approved_targets=frozenset({"synthetic-target"}),
            approved_tools=frozenset(TOOLS),
            intrusive_approvals=frozenset(),
            max_actions=20,
        )

    def test_locked_inventory_and_read_only_plan(self):
        self.assertEqual(len(TOOLS), 20)
        self.assertEqual(len(set(TOOLS)), 20)
        result = plan_tools(
            ("Trivy",), "synthetic-target", self.engagement,
            (Capability("Trivy", True, True, True),),
        )
        self.assertTrue(result["results"][0]["eligible"])
        self.assertFalse(result["execution_authorized"])
        self.assertNotIn("command", result["results"][0])

    def test_missing_tool_and_prerequisites_fail_closed(self):
        for caps, expected in (
            ((), "capability_not_verified"),
            ((Capability("Trivy", False, True, True),), "tool_unavailable"),
            ((Capability("Trivy", True, False, True),), "prerequisites_unverified"),
            ((Capability("Trivy", True, True, False),), "platform_unsupported"),
        ):
            result = plan_tools(("Trivy",), "synthetic-target", self.engagement, caps)
            self.assertEqual(result["results"][0]["reason"], expected)
            self.assertFalse(result["results"][0]["eligible"])

    def test_intrusive_requires_separate_approval(self):
        result = plan_tools(("MITRE CALDERA",), "synthetic-target", self.engagement,
                            (Capability("MITRE CALDERA", True, True, True),))
        self.assertEqual(result["results"][0]["reason"], "intrusive_approval_missing")

    def test_scope_stop_budget_and_unknown_fail_closed(self):
        caps = (Capability("Trivy", True, True, True),)
        for target, engagement, requested in (
            ("outside", self.engagement, ("Trivy",)),
            ("synthetic-target", Engagement(frozenset({"synthetic-target"}),
                                            frozenset(TOOLS), frozenset(), 20, True), ("Trivy",)),
            ("synthetic-target", Engagement(frozenset({"synthetic-target"}),
                                            frozenset(TOOLS), frozenset(), 0), ("Trivy",)),
            ("synthetic-target", self.engagement, ("Unknown",)),
            ("synthetic-target", self.engagement, ("Trivy", "Trivy")),
        ):
            with self.assertRaises(ValueError):
                plan_tools(requested, target, engagement, caps)

    def test_malformed_authority_records_fail_closed(self):
        valid = frozenset({"synthetic-target"})
        tools = frozenset({"Trivy"})
        caps = (Capability("Trivy", True, True, True),)
        malformed = (
            Engagement(valid, tools, frozenset(), 1, "false"),
            Engagement(valid, tools, frozenset(), 1, 0),
            Engagement(["synthetic-target"], tools, frozenset(), 1),
            Engagement(valid, ["Trivy"], frozenset(), 1),
            Engagement(valid, tools, ["Metasploit Framework"], 1),
            Engagement(frozenset({None}), tools, frozenset(), 1),
            Engagement(valid, frozenset({"Unknown"}), frozenset(), 1),
            Engagement(valid, tools, frozenset({"Trivy"}), 1),
        )
        for engagement in malformed:
            with self.subTest(engagement=engagement), self.assertRaises(ValueError):
                plan_tools(("Trivy",), "synthetic-target", engagement, caps)

    def test_unknown_capability_cannot_be_silently_accepted(self):
        with self.assertRaises(ValueError):
            plan_tools(("Trivy",), "synthetic-target", self.engagement,
                       (Capability("Trivy", True, True, True),
                        Capability("Unregistered", True, True, True)))

    def test_tool_not_authorized_even_when_available(self):
        engagement = Engagement(frozenset({"synthetic-target"}), frozenset(), frozenset(), 1)
        result = plan_tools(("Trivy",), "synthetic-target", engagement,
                            (Capability("Trivy", True, True, True),))
        self.assertEqual(result["results"][0]["reason"], "tool_not_authorized")


if __name__ == "__main__":
    unittest.main()
