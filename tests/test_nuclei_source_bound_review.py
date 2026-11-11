"""Source-bound offline Nuclei review safety and provenance regressions."""
import hashlib
import json
import unittest

from nightrecon_red_engine.nuclei_operator_triage import NucleiTriageError
from nightrecon_red_engine.nuclei_source_bound_review import review_nuclei_source


def fixture():
    row = {"template-id": "safe-test", "matched-at": "https://example.test/a",
           "info": {"severity": "low"}, "request": "PRIVATE"}
    return json.dumps(row).encode("utf-8")


class SourceBoundNucleiReviewTests(unittest.TestCase):
    def review(self, payload=None, digest=None, **kwargs):
        payload = fixture() if payload is None else payload
        digest = hashlib.sha256(payload).hexdigest() if digest is None else digest
        return review_nuclei_source(
            payload, engagement_id="approved-lab",
            authorized_hosts=("example.test",),
            expected_source_sha256=digest, **kwargs,
        )

    def test_reproducible_source_bound_review_without_secret_leak(self):
        report = self.review()
        self.assertEqual(report, self.review())
        self.assertEqual(report["source_sha256"], hashlib.sha256(fixture()).hexdigest())
        self.assertEqual(report["source_binding"], "verified_against_supplied_pinned_digest")
        self.assertEqual(report["confirmed_findings"], 0)
        self.assertFalse(report["external_execution"])
        self.assertNotIn("PRIVATE", str(report))
        self.assertNotIn("/a", str(report))

    def test_tampered_payload_and_invalid_digest_fail_closed(self):
        original_digest = hashlib.sha256(fixture()).hexdigest()
        for payload, digest in (
            (fixture() + b" ", original_digest),
            (fixture(), "0" * 64),
            (fixture(), "NOT-A-DIGEST"),
            (fixture(), original_digest.upper()),
        ):
            with self.subTest(payload=payload, digest=digest), self.assertRaises(NucleiTriageError):
                self.review(payload=payload, digest=digest)

    def test_scope_and_review_decisions_fail_closed(self):
        with self.assertRaises(ValueError):
            review_nuclei_source(
                fixture(), engagement_id="approved-lab",
                authorized_hosts=("other.test",),
                expected_source_sha256=hashlib.sha256(fixture()).hexdigest(),
            )
        with self.assertRaises(NucleiTriageError):
            self.review(decisions={"unknown": "confirmed"})
        with self.assertRaises(ValueError):
            self.review(max_bytes=1)

    def test_bounded_review_cannot_confirm_findings(self):
        report = self.review()
        identifier = report["observations"][0]["observation_id"]
        reviewed = self.review(decisions={identifier: "follow_up_required"})
        self.assertEqual(reviewed["confirmed_findings"], 0)
        self.assertEqual(reviewed["observations"][0]["operator_disposition"], "follow_up_required")
        self.assertNotEqual(report["report_sha256"], reviewed["report_sha256"])


if __name__ == "__main__":
    unittest.main()
