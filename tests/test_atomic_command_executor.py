import json
import sys
import threading
import subprocess
import tempfile
import unittest
from datetime import datetime,timedelta,timezone
from pathlib import Path
from nightrecon_red_engine.atomic_action_ledger import AtomicActionLedger
from nightrecon_red_engine.governed_command_runner import FixedCommand
from nightrecon_red_engine.atomic_command_executor import execute_atomically_governed
from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy,FileEngagementPolicyStore

class TestAtomicExecutor(unittest.TestCase):
    def setUp(self):
        td=tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root=Path(td.name)
        self.store=FileEngagementPolicyStore(root/"policy.json")
        self.ledger=AtomicActionLedger(root/"actions.db")
        self.audit=root/"auth.jsonl"
        self.results=root/"results.jsonl"
        now=datetime.now(timezone.utc)
        self.store.set_policy(EngagementExecutionPolicy(
            engagement_id="lab",scope=("192.0.2.1",),
            valid_from=(now-timedelta(minutes=5)).isoformat(),
            valid_until=(now+timedelta(minutes=5)).isoformat(),
            max_actions=2,permitted_capabilities=("external.local.diagnostics",),
            max_impact="low"))
        self.ledger.provision("lab",limit=2)
        self.command=FixedCommand("python-version",Path(sys.executable),("--version",),
                                  "external.local.diagnostics")
    def run_it(self, action_id="one", target="192.0.2.1"):
        return execute_atomically_governed(
            command=self.command,action_id=action_id,engagement_id="lab",
            engagement_status="active",target=target,policy_store=self.store,
            ledger=self.ledger,audit_path=self.audit,result_audit_path=self.results)
    def test_execution_and_structured_audit(self):
        result=self.run_it()
        self.assertEqual(result.returncode,0)
        records=[json.loads(line) for line in self.results.read_text().splitlines()]
        self.assertEqual([r["status"] for r in records],["started","completed"])
        self.assertNotIn("stdout",records[1])
    def test_duplicate_action_rejected(self):
        self.run_it()
        with self.assertRaises(PermissionError):
            self.run_it()
    def test_revoked_ledger_blocks(self):
        self.ledger.revoke("lab")
        with self.assertRaises(PermissionError):
            self.run_it()
    def test_out_of_scope_blocks_without_results(self):
        with self.assertRaises(PermissionError):
            self.run_it(target="198.51.100.2")
        self.assertFalse(self.results.exists())

class TestCancellation(unittest.TestCase):
    def test_pre_cancelled_operation_terminates_child(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            now=datetime.now(timezone.utc)
            store=FileEngagementPolicyStore(root/"policy.json")
            store.set_policy(EngagementExecutionPolicy(
                engagement_id="lab",scope=("192.0.2.1",),
                valid_from=(now-timedelta(minutes=5)).isoformat(),
                valid_until=(now+timedelta(minutes=5)).isoformat(),
                max_actions=2,permitted_capabilities=("external.local.diagnostics",),
                max_impact="low",
            ))
            ledger=AtomicActionLedger(root/"actions.db")
            ledger.provision("lab",limit=2)
            event=threading.Event()
            event.set()
            command=FixedCommand("sleeping",Path(sys.executable),
                ("-c","import time;time.sleep(2)"),"external.local.diagnostics",
                timeout_seconds=4)
            with self.assertRaises(InterruptedError):
                execute_atomically_governed(
                    command=command,action_id="cancel",engagement_id="lab",
                    engagement_status="active",target="192.0.2.1",
                    policy_store=store,ledger=ledger,audit_path=root/"auth.jsonl",
                    result_audit_path=root/"results.jsonl",cancel_event=event)
            records=[json.loads(line) for line in (root/"results.jsonl").read_text().splitlines()]
            self.assertEqual(records[-1]["status"],"cancelled")
