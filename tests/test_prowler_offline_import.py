"""Synthetic Prowler importer tests; never contact cloud services."""
import json
import unittest

from nightrecon_red_engine.prowler_offline_import import import_prowler_json, ProwlerEvidenceError


class ProwlerOfflineTests(unittest.TestCase):
    def test_exact_account_and_unverified_evidence(self):
        payload = json.dumps([{"account_uid": "acct-a", "check_id": "check-1",
                               "resource_uid": "resource-1", "status": "FAIL"}]).encode()
        result = import_prowler_json(payload, approved_account="acct-a")
        self.assertEqual(result["finding_count"], 1)
        self.assertEqual(result["authority"], "evidence_only_not_authorization")
        self.assertEqual(result["findings"][0]["evidence_state"], "unverified_third_party_observation")
        self.assertEqual(result, import_prowler_json(payload, approved_account="acct-a"))

    def test_out_of_scope_and_malformed_fail_closed(self):
        for records in ([{"account_uid": "acct-b", "check_id": "x", "resource_uid": "r", "status": "FAIL"}],
                        [{"account_uid": "acct-a", "check_id": "x", "resource_uid": "r", "status": "UNKNOWN"}],
                        [{"account_uid": "acct-a", "check_id": "x", "status": "FAIL"}]):
            with self.assertRaises(ProwlerEvidenceError):
                import_prowler_json(json.dumps(records).encode(), approved_account="acct-a")
        with self.assertRaises(ProwlerEvidenceError):
            import_prowler_json(b"{}", approved_account="acct-a")
        with self.assertRaises(ProwlerEvidenceError):
            import_prowler_json(b"not-json", approved_account="acct-a")

    def test_budget_and_empty_authority(self):
        payload = json.dumps([{"account_uid": "acct-a", "check_id": "x",
                               "resource_uid": "r", "status": "PASS"}] * 2).encode()
        with self.assertRaises(ProwlerEvidenceError):
            import_prowler_json(payload, approved_account="acct-a", max_findings=1)
        with self.assertRaises(ProwlerEvidenceError):
            import_prowler_json(payload, approved_account="")
        with self.assertRaises(ProwlerEvidenceError):
            import_prowler_json(payload, approved_account="acct-a", max_bytes=5)


if __name__ == "__main__":
    unittest.main()
