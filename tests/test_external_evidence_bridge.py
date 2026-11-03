import unittest
from nightrecon_red_engine.evidence_correlation import EvidenceSummary,HostEvidence
from nightrecon_red_engine.external_evidence_bridge import build_external_evidence

class TestExternalEvidenceBridge(unittest.TestCase):
    def setUp(self):
        self.summary=EvidenceSummary(
            "unverified-imported-evidence",
            (HostEvidence("192.0.2.1",True,True,(("tcp",443,"open","https"),)),),
            (),("nmap-xml-unverified","pcap-metadata-unverified"),
        )
        self.args=dict(engagement_id="engagement-1",summary=self.summary,
                       allowed_addresses=frozenset({"192.0.2.1"}),
                       observed_at="2026-10-09T00:00:00+00:00")
    def test_produces_native_evidence_with_limitations(self):
        record=build_external_evidence(**self.args)[0]
        self.assertEqual(record.source_night,"red")
        self.assertEqual(record.evidence_type,"external-network-observation")
        self.assertEqual(record.data["verification"],"unverified")
        self.assertEqual(record.data["address"],"192.0.2.1")
        self.assertTrue(record.limitations)
        self.assertEqual(record.to_dict()["engagement_id"],"engagement-1")
    def test_stable_evidence_id(self):
        a=build_external_evidence(**self.args)[0]
        b=build_external_evidence(**self.args)[0]
        self.assertEqual(a.evidence_id,b.evidence_id)
    def test_rejects_host_outside_scope(self):
        with self.assertRaisesRegex(ValueError,"outside"):
            build_external_evidence(**{**self.args,"allowed_addresses":frozenset()})
    def test_no_hosts_produce_no_evidence(self):
        empty=EvidenceSummary("unverified-imported-evidence",(),(),())
        self.assertEqual(build_external_evidence(**{**self.args,"summary":empty}),())
