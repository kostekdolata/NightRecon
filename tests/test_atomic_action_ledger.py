import concurrent.futures
import tempfile
import unittest
from pathlib import Path
from nightrecon_red_engine.atomic_action_ledger import AtomicActionLedger

class TestAtomicLedger(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.ledger=AtomicActionLedger(Path(temp.name)/"ledger.sqlite")
    def test_concurrent_budget_never_exceeded(self):
        self.ledger.provision("lab",limit=3)
        def run(i):
            try:
                return self.ledger.reserve("lab",str(i))
            except PermissionError:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results=list(pool.map(run,range(16)))
        approved=[r for r in results if r is not None]
        self.assertEqual(len(approved),3)
        self.assertEqual(sorted(r.used for r in approved),[1,2,3])
    def test_duplicate_request_denied(self):
        self.ledger.provision("lab",limit=2)
        self.ledger.reserve("lab","one")
        with self.assertRaises(PermissionError):
            self.ledger.reserve("lab","one")
    def test_unknown_and_revoked_denied(self):
        with self.assertRaises(PermissionError):
            self.ledger.reserve("unknown","one")
        self.ledger.provision("lab",limit=2)
        self.ledger.revoke("lab")
        with self.assertRaises(PermissionError):
            self.ledger.reserve("lab","one")
    def test_reprovision_cannot_increase_budget_or_unrevoke(self):
        self.ledger.provision("lab",limit=1,revoked=True)
        self.ledger.provision("lab",limit=20,revoked=False)
        with self.assertRaises(PermissionError):
            self.ledger.reserve("lab","one")

    def test_authoritative_policy_limit_tightens_budget(self):
        self.ledger.provision("limited", limit=20)
        self.ledger.reserve("limited", "first", policy_limit=2)
        self.ledger.reserve("limited", "second", policy_limit=20)
        with self.assertRaises(PermissionError):
            self.ledger.reserve("limited", "third", policy_limit=20)

    def test_external_policy_usage_is_accounted_for(self):
        self.ledger.provision("shared", limit=5)
        self.ledger.reserve("shared", "first", policy_limit=5, policy_used=4)
        with self.assertRaises(PermissionError):
            self.ledger.reserve("shared", "second", policy_limit=5)

    def test_invalid_authoritative_policy_values_rejected(self):
        self.ledger.provision("limited", limit=3)
        with self.assertRaises(ValueError):
            self.ledger.reserve("limited", "one", policy_limit=True)
        with self.assertRaises(ValueError):
            self.ledger.reserve("limited", "one", policy_used=-1)
