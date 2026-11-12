"""Synthetic, network-free Greenbone evidence contract regression tests."""
import hashlib
import unittest

from nightrecon_red_engine.greenbone_offline_evidence import (
    GreenboneEvidenceError, import_greenbone_xml,
)


def report(host="127.0.0.1", severity="5.0", port="443/tcp", oid="1.3.6.1"):
    return (f"<report><results><result><host>{host}</host>"
            f"<nvt oid=\"{oid}\"/><port>{port}</port>"
            f"<severity>{severity}</severity></result></results></report>").encode()


class GreenboneOfflineEvidenceTests(unittest.TestCase):
    def test_valid_report_redacts_identity_and_does_not_grant_authority(self):
        payload = report()
        result = import_greenbone_xml(payload, approved_hosts=("127.0.0.1",))
        self.assertEqual(result["source_report_sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(result["unique_observation_count"], 1)
        self.assertEqual(result["authority"], "evidence_only_not_authorization")
        self.assertEqual(result["observations"][0]["exploitability"], "not_established")
        self.assertNotIn("127.0.0.1", str(result))
        self.assertEqual(result, import_greenbone_xml(payload, approved_hosts=("127.0.0.1",)))

    def test_exact_scope_and_bad_records_fail_closed(self):
        bad = [report(host="127.0.0.2"), report(port="0/tcp"),
               report(port="443/xyz"), report(severity="nan"),
               report(severity="11"), report(oid="not-oid"),
               b"<report><results><result></results></report>",
               b'<!DOCTYPE report [<!ENTITY x "evil">]><report/>',
               b"<report><results><result/><result/></results></report>"]
        for payload in bad:
            with self.subTest(payload=payload), self.assertRaises(GreenboneEvidenceError):
                import_greenbone_xml(payload, approved_hosts=("127.0.0.1",), max_results=1)

    def test_missing_tool_never_assumed_and_budgets_are_strict(self):
        for scope, budget in [((), 1), (("127.0.0.1",), 0),
                              (("127.0.0.1",), True)]:
            with self.assertRaises(GreenboneEvidenceError):
                import_greenbone_xml(report(), approved_hosts=scope, max_results=budget)
        with self.assertRaises(GreenboneEvidenceError):
            import_greenbone_xml(report() * 100000, approved_hosts=("127.0.0.1",))
