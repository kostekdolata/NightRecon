"""Autonomous Red operator is plan-only and policy constrained."""

from __future__ import annotations

from datetime import datetime, timezone
import tempfile
import unittest

from nightrecon_red_engine.autonomous_operator import (
    OperatorContext,
    OperatorProposal,
    compile_autonomous_plan,
)
from nightrecon_shared_core.contracts import EngagementMetadata
from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy
from nightrecon_shared_core.workspace import LocalWorkspace


class FakeAgent:
    def __init__(self, proposals):
        self.proposals = proposals
        self.calls = 0

    def propose(self, context):
        self.calls += 1
        return self.proposals


def workspace(root):
    ws = LocalWorkspace(root)
    ws.create_engagement(EngagementMetadata(
        engagement_id="eng-auto",
        name="Autonomous plan lab",
        created_at="2026-09-28T00:00:00+00:00",
        authorization_reference="approval://eng-auto",
        status="active",
    ))
    ws.set_execution_policy(EngagementExecutionPolicy(
        engagement_id="eng-auto",
        scope=("192.0.2.0/24",),
        valid_from="2026-09-28T00:00:00+00:00",
        valid_until="2026-09-29T00:00:00+00:00",
        max_actions=5,
        permitted_capabilities=("discovery", "scan", "validation.run"),
    ))
    return ws


class AutonomousOperatorTests(unittest.TestCase):
    def test_plan_filters_unknown_out_of_scope_and_high_impact_steps(self):
        with tempfile.TemporaryDirectory() as root:
            ws = workspace(root)
            agent = FakeAgent((
                OperatorProposal("discovery", "192.0.2.10", "Map approved target."),
                OperatorProposal("scan", "198.51.100.10", "Inspect outside target."),
                OperatorProposal("validation.run", "192.0.2.10", "Prove finding."),
                OperatorProposal("shell.exec", "192.0.2.10", "Run arbitrary command."),
            ))
            plan = compile_autonomous_plan(
                ws, agent,
                OperatorContext("eng-auto", "Assess the approved service."),
                now=datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc),
            )
            self.assertEqual(agent.calls, 1)
            self.assertEqual(
                tuple(step.status for step in plan.steps),
                ("allowed", "blocked", "blocked", "blocked"),
            )
            self.assertEqual(plan.steps[1].reason_code, "target_out_of_scope")
            self.assertEqual(plan.steps[2].reason_code, "approval_required")
            self.assertEqual(plan.steps[3].reason_code, "unknown_capability")
            self.assertEqual(plan.execution_mode, "plan-only")
            self.assertEqual(
                LocalWorkspace(root).execution_policy("eng-auto").actions_used, 0
            )

    def test_approved_high_impact_step_can_be_planned_but_not_executed(self):
        with tempfile.TemporaryDirectory() as root:
            plan = compile_autonomous_plan(
                workspace(root),
                FakeAgent((
                    OperatorProposal(
                        "validation.run", "192.0.2.10", "Approved proof.",
                        approval_present=True,
                    ),
                )),
                OperatorContext("eng-auto", "Validate the approved condition."),
                now=datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc),
            )
            self.assertEqual(plan.steps[0].status, "allowed")
            self.assertEqual(plan.steps[0].reason_code, "authorized")
            self.assertIn("No command", plan.limitations[0])

    def test_step_limit_truncates_agent_output(self):
        with tempfile.TemporaryDirectory() as root:
            proposals = tuple(
                OperatorProposal("discovery", "192.0.2.10", f"Step {index}")
                for index in range(5)
            )
            plan = compile_autonomous_plan(
                workspace(root), FakeAgent(proposals),
                OperatorContext("eng-auto", "Bounded plan", max_steps=2),
                now=datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc),
            )
            self.assertTrue(plan.truncated)
            self.assertEqual(len(plan.steps), 2)


if __name__ == "__main__":
    unittest.main()
