import concurrent.futures
import tempfile
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
