import tempfile
import unittest
from pathlib import Path
from nightrecon_red_engine.finding_review_store import FindingStore,FindingRecord

class TestFindingStore(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store=FindingStore(Path(self.tmp.name)/"review.db")
    def test_deduplication_and_engagement_isolation(self):
        record=FindingRecord("eng1","192.0.2.1","check-1","open","evidence-1","")
        self.store.upsert(record)
        self.store.upsert(record)
        self.assertEqual(len(self.store.list_findings("eng1")),1)
        self.assertEqual(self.store.list_findings("eng2"),())
    def test_retest_requires_evidence(self):
        self.store.upsert(FindingRecord("eng1","asset","check","open","ev1",""))
        with self.assertRaises(ValueError):
            self.store.retest("eng1","asset","check","",False)
        self.store.retest("eng1","asset","check","ev2",False)
        self.assertEqual(self.store.list_findings("eng1")[0].status,"resolved")
    def test_invalid_status(self):
        with self.assertRaises(ValueError):
            self.store.upsert(FindingRecord("eng1","asset","check","confirmed-exploitable","ev1",""))
    def test_missing_retest_finding(self):
        with self.assertRaises(KeyError):
            self.store.retest("eng1","asset","missing","ev2",True)
