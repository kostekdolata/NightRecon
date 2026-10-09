import concurrent.futures
import tempfile
import sys
import json
from nightrecon_red_engine.atomic_command_executor import execute_atomically_governed
from nightrecon_red_engine.governed_command_runner import FixedCommand
import unittest
from datetime import datetime,timedelta,timezone
from pathlib import Path
from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy
from nightrecon_red_engine.transactional_policy_authority import TransactionalPolicyAuthority

class TestTransactionalPolicyAuthority(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.authority=TransactionalPolicyAuthority(Path(t.name)/"authority.db")
        now=datetime.now(timezone.utc)
        self.authority.register(EngagementExecutionPolicy(
            engagement_id="lab",scope=("192.0.2.1",),
            valid_from=(now-timedelta(minutes=5)).isoformat(),
            valid_until=(now+timedelta(minutes=5)).isoformat(),
            max_actions=3,
            permitted_capabilities=("external.local.diagnostics",),
            max_impact="low"),status="active")
    def reserve(self,action_id,target="192.0.2.1"):
        return self.authority.reserve(engagement_id="lab",action_id=action_id,
            capability="external.local.diagnostics",target=target,impact="low")
    def test_concurrent_workers_never_exceed_budget(self):
        def attempt(i):
            try: return self.reserve(str(i))
            except PermissionError: return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            results=list(pool.map(attempt,range(20)))
        self.assertEqual(len([v for v in results if v is not None]),3)
    def test_revoke_blocks_further_reservations(self):
        self.reserve("first")
        self.authority.revoke("lab")
        with self.assertRaises(PermissionError): self.reserve("second")
    def test_paused_engagement_blocks(self):
        self.authority.set_status("lab","paused")
        with self.assertRaises(PermissionError): self.reserve("first")
    def test_scope_blocks(self):
        with self.assertRaisesRegex(PermissionError,"target_out_of_scope"):
            self.reserve("first","198.51.100.1")
    def test_duplicate_action_rejected(self):
        self.reserve("one")
        with self.assertRaises(PermissionError): self.reserve("one")

    def test_executor_uses_transactional_authority(self):
        from nightrecon_shared_core.engagement_policy import FileEngagementPolicyStore
        from nightrecon_red_engine.atomic_action_ledger import AtomicActionLedger
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            command=FixedCommand("version",Path(sys.executable),("--version",),
                "external.local.diagnostics",impact="low")
            result=execute_atomically_governed(
                command=command,action_id="execute",engagement_id="lab",
                engagement_status="active",target="192.0.2.1",
                policy_store=FileEngagementPolicyStore(root/"unused.json"),
                ledger=AtomicActionLedger(root/"unused.db"),
                audit_path=root/"auth.jsonl",
                result_audit_path=root/"results.jsonl",
                authority=self.authority)
            self.assertEqual(result.returncode,0)
            with self.assertRaises(PermissionError):
                self.reserve("execute")

    def test_legacy_import_requires_explicit_status_and_is_atomic(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            other=TransactionalPolicyAuthority(root/"import.db")
            from nightrecon_shared_core.engagement_policy import FileEngagementPolicyStore
            legacy=FileEngagementPolicyStore(root/"legacy.json")
            with self.authority._db() as connection:
                row=connection.execute("SELECT policy_json FROM engagement_authority").fetchone()
            legacy.set_policy(EngagementExecutionPolicy.from_dict(json.loads(row[0])))
            with self.assertRaises(ValueError):
                other.import_legacy(root/"legacy.json",statuses={})
            self.assertEqual(other.import_legacy(root/"legacy.json",statuses={"lab":"paused"}),1)
            with self.assertRaises(Exception):
                other.import_legacy(root/"legacy.json",statuses={"lab":"active"})
            with self.assertRaises(PermissionError):
                other.reserve(engagement_id="lab",action_id="blocked",
                    capability="external.local.diagnostics",target="192.0.2.1",impact="low")
