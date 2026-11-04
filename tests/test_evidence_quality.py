"""Read-only evidence quality regression tests."""

from dataclasses import replace
import unittest

from nightrecon_red_engine.evidence_correlation import EvidenceSummary, HostEvidence
from nightrecon_red_engine.external_evidence_bridge import build_external_evidence
from nightrecon_red_engine.evidence_quality import assess_imported_evidence


class ImportedEvidenceQualityTests(unittest.TestCase):
    def setUp(self):
        summary = EvidenceSummary(
            "unverified-imported-evidence",
            (HostEvidence("192.0.2.1", True, True, (("tcp", 443, "open", "https"),)),),
            (),
            ("nmap-xml-unverified", "pcap-metadata-unverified"),
        )
        self.record = build_external_evidence(
            engagement_id="eng-1",
            summary=summary,
            allowed_addresses=frozenset({"192.0.2.1"}),
            observed_at="2026-10-09T00:00:00+00:00",
        )[0]

    def test_valid_import_remains_unverified_even_with_two_sources(self):
        quality = assess_imported_evidence((self.record,))
        self.assertEqual(len(quality), 1)
        self.assertEqual(quality[0].verification, "unverified")
        self.assertEqual(quality[0].source_count, 2)
        self.assertTrue(quality[0].requires_independent_validation)
        self.assertEqual(quality[0].limitations, self.record.limitations)

    def test_rejects_forged_verification(self):
        forged = replace(self.record, data={**self.record.data, "verification": "confirmed"})
        with self.assertRaisesRegex(ValueError, "unverified"):
            assess_imported_evidence((forged,))

    def test_rejects_wrong_provenance(self):
        forged = replace(self.record, provenance="first-party-validation")
        with self.assertRaisesRegex(ValueError, "provenance"):
            assess_imported_evidence((forged,))

    def test_requires_source_and_limitations(self):
        with self.assertRaisesRegex(ValueError, "source"):
            assess_imported_evidence((replace(self.record, data={**self.record.data, "import_sources": []}),))
        with self.assertRaisesRegex(ValueError, "limitations"):
            assess_imported_evidence((replace(self.record, limitations=()),))

    def test_rejects_duplicate_ids_and_returns_empty_for_empty_input(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            assess_imported_evidence((self.record, self.record))
        self.assertEqual(assess_imported_evidence(()), ())


if __name__ == "__main__":
    unittest.main()
