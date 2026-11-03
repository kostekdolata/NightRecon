import json
import tempfile
import unittest
from datetime import datetime,timedelta,timezone
from pathlib import Path
from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy
from nightrecon_red_engine.transactional_policy_authority import TransactionalPolicyAuthority
from nightrecon_red_engine.transactional_local_diagnostic import execute_transactional_local_diagnostic

class TestTransactionalLocalDiagnostic(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root=Path(t.name)
        self.authority=TransactionalPolicyAuthority(self.root/"auth.sqlite")
        now=datetime.now(timezone.utc)
        self.authority.register(EngagementExecutionPolicy(
            engagement_id="lab",scope=("192.0.2.1",),
            valid_from=(now-timedelta(minutes=5)).isoformat(),
            valid_until=(now+timedelta(minutes=5)).isoformat(),
            max_actions=1,permitted_capabilities=("external.local.diagnostics",),
            max_impact="low"),status="active")
    def execute(self, **overrides):
        args=dict(authority=self.authority,engagement_id="lab",action_id="one",
            target="192.0.2.1",diagnostic_name="local-python-version",
            audit_path=self.root/"auth.jsonl",result_audit_path=self.root/"results.jsonl")
        args.update(overrides)
        return execute_transactional_local_diagnostic(**args)
    def test_allowlisted_diagnostic_executes(self):
        self.assertEqual(self.execute().returncode,0)
        self.assertEqual(json.loads((self.root/"results.jsonl").read_text().splitlines()[-1])["status"],"completed")
    def test_budget_and_duplicate_execution_blocked(self):
        self.execute()
        with self.assertRaises(PermissionError):
            self.execute(action_id="two")
    def test_unknown_diagnostic_does_not_consume_budget(self):
        with self.assertRaises(PermissionError):
            self.execute(diagnostic_name="shell")
        self.assertEqual(self.execute().returncode,0)
    def test_scope_violation_blocks(self):
        with self.assertRaises(PermissionError):
            self.execute(target="198.51.100.10")
