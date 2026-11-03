import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from nightrecon_shared_core.engagement_policy import (
    EngagementExecutionPolicy, FileEngagementPolicyStore,
    read_authorization_audit,
)
from nightrecon_red_engine.governed_tool_planner import plan_governed_tool


class TestGovernedPlanner(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.store = FileEngagementPolicyStore(root / "policy.json")
        self.audit = root / "audit.jsonl"
        now = datetime.now(timezone.utc)
        self.store.set_policy(EngagementExecutionPolicy(
            engagement_id="test",
            scope=("192.0.2.10",),
            valid_from=(now - timedelta(minutes=5)).isoformat(),
            valid_until=(now + timedelta(minutes=5)).isoformat(),
            max_actions=2,
            permitted_capabilities=("external.nmap.discovery",),
            max_impact="standard",
        ))
    def plan(self, target="192.0.2.10", tool="nmap-discovery", status="active"):
        return plan_governed_tool(
            tool=tool, target=target, engagement_id="test",
            engagement_status=status, policy_store=self.store,
            audit_path=self.audit,
        )
    def test_authorised_plan_is_not_execution(self):
        plan = self.plan()
        self.assertTrue(plan.authorised)
        self.assertEqual(plan.mode, "plan-only")
        self.assertEqual(len(read_authorization_audit(self.audit)), 1)
        self.assertEqual(self.store.policy("test").actions_used, 0)
    def test_outside_scope_denied_and_audited(self):
        plan = self.plan(target="198.51.100.1")
        self.assertFalse(plan.authorised)
        self.assertEqual(plan.reason_code, "target_out_of_scope")
        self.assertEqual(len(read_authorization_audit(self.audit)), 1)
    def test_unpermitted_tool_denied(self):
        plan = self.plan(tool="tshark-inspection")
        self.assertFalse(plan.authorised)
        self.assertEqual(plan.reason_code, "capability_not_permitted")
    def test_inactive_engagement_denied(self):
        self.assertEqual(self.plan(status="paused").reason_code, "engagement_not_active")
    def test_unknown_tool_fail_closed(self):
        with self.assertRaises(ValueError):
            self.plan(tool="arbitrary-command")
    def test_missing_policy_fail_closed(self):
        with self.assertRaises(PermissionError):
            plan_governed_tool(
                tool="nmap-discovery", target="192.0.2.10",
                engagement_id="unknown", engagement_status="active",
                policy_store=self.store, audit_path=self.audit,
            )
