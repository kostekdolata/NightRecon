import tempfile
import unittest
from datetime import datetime,timedelta,timezone
from pathlib import Path
from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy,FileEngagementPolicyStore,read_authorization_audit
from nightrecon_red_engine.governed_offline_worker import run_offline_operation

class GovernedOfflineWorkerTest(unittest.TestCase):
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
            max_actions=1,permitted_capabilities=("external.tshark.inspect",),
            max_impact="low",
        ))
    def run(self,**kwargs):
        return run_offline_operation(
            operation="inspect-imported-capture",engagement_id="lab",
            engagement_status="active",target="192.0.2.1",
            policy_store=self.store,audit_path=self.audit,
            work=lambda:"parsed",**kwargs,
        )
    def test_reserves_before_offline_work(self):
        result=self.run()
        self.assertEqual(result.result,"parsed")
        self.assertEqual(self.store.policy("lab").actions_used,1)
        self.assertEqual(len(read_authorization_audit(self.audit)),2)
    def test_exhausted_budget_blocks_second_run(self):
        self.run()
        with self.assertRaises(PermissionError):
            self.run()
    def test_out_of_scope_cannot_execute_callback(self):
        called=[]
        with self.assertRaises(PermissionError):
            run_offline_operation(
                operation="inspect-imported-capture",engagement_id="lab",
                engagement_status="active",target="198.51.100.2",
                policy_store=self.store,audit_path=self.audit,
                work=lambda:called.append(True),
            )
        self.assertEqual(called,[])
        self.assertEqual(self.store.policy("lab").actions_used,0)
    def test_unknown_operation_is_rejected(self):
        with self.assertRaises(ValueError):
            run_offline_operation(
                operation="nmap-execute",engagement_id="lab",
                engagement_status="active",target="192.0.2.1",
                policy_store=self.store,audit_path=self.audit,work=lambda:None,
            )
