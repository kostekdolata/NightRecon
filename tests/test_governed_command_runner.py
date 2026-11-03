import sys
import tempfile
import unittest
from datetime import datetime,timedelta,timezone
from pathlib import Path
from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy,FileEngagementPolicyStore,read_authorization_audit
from nightrecon_red_engine.governed_command_runner import FixedCommand,execute_fixed_command

class TestGovernedCommandRunner(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root=Path(tmp.name)
        self.store=FileEngagementPolicyStore(root/"policy.json")
        self.audit=root/"audit.jsonl"
        now=datetime.now(timezone.utc)
        self.store.set_policy(EngagementExecutionPolicy(
            engagement_id="lab",scope=("192.0.2.1",),
            valid_from=(now-timedelta(hours=1)).isoformat(),
            valid_until=(now+timedelta(hours=1)).isoformat(),
            max_actions=2,permitted_capabilities=("external.local.diagnostics",),
            max_impact="low",
        ))
        self.cmd=FixedCommand(
            "python-version",Path(sys.executable),("--version",),
            "external.local.diagnostics",
        )
    def run_cmd(self,target="192.0.2.1"):
        return execute_fixed_command(command=self.cmd,engagement_id="lab",
            engagement_status="active",target=target,
            policy_store=self.store,audit_path=self.audit)
    def test_fixed_command_runs_without_shell(self):
        result=self.run_cmd()
        self.assertEqual(result.returncode,0)
        self.assertIn("Python",result.stdout+result.stderr)
        self.assertEqual(self.store.policy("lab").actions_used,1)
        self.assertEqual(len(read_authorization_audit(self.audit)),2)
    def test_out_of_scope_denied(self):
        with self.assertRaises(PermissionError): self.run_cmd("198.51.100.20")
        self.assertEqual(self.store.policy("lab").actions_used,0)
    def test_elevated_definition_denied(self):
        with self.assertRaisesRegex(ValueError,"broker"):
            FixedCommand("elevated",Path(sys.executable),("--version",),
                         "external.local.diagnostics",elevated=True)
    def test_relative_executable_denied(self):
        with self.assertRaisesRegex(ValueError,"absolute"):
            FixedCommand("bad",Path("python"),("--version",),"external.local.diagnostics")
