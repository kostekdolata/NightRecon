"""Tests for identity evidence coverage review."""

import unittest

from nightrecon_red_engine.graph_identity_evidence import (
    IdentityEvidence,
    IdentityEvidenceBundle,
)
from nightrecon_red_engine.identity_collection import IdentityCollectionResult
from nightrecon_red_engine.identity_coverage_review import (
    build_identity_coverage_review,
)


class IdentityCoverageReviewTests(unittest.TestCase):
    def test_collection_without_permissions_keeps_acl_gate_open(self):
        result = IdentityCollectionResult(
            source_type="active-directory",
            target="dc.example.test",
            entry_count=1,
            unresolved_members=0,
            evidence=IdentityEvidenceBundle(
                identities=(
                    IdentityEvidence(
                        natural_key="identity:1",
                        label="opaque",
                        source_id="fixture",
                        identity_type="ad-user",
                    ),
                ),
            ),
        )

        review = build_identity_coverage_review(result)

        self.assertEqual(review.level, "collected")
        self.assertEqual(review.identities, 1)
        self.assertEqual(review.permissions, 0)
        self.assertTrue(any(
            "ACL/security-descriptor" in item
            for item in review.open_acceptance_gates
        ))
        self.assertTrue(any(
            "specialist-tool comparison" in item
            for item in review.open_acceptance_gates
        ))

    def test_truncation_and_unresolved_members_are_explicit(self):
        result = IdentityCollectionResult(
            source_type="active-directory",
            target="dc.example.test",
            entry_count=0,
            unresolved_members=2,
            evidence=IdentityEvidenceBundle.empty(),
            truncated=True,
            limitations=("provider ceiling reached",),
        )

        review = build_identity_coverage_review(result)

        self.assertEqual(review.level, "limited")
        self.assertIn("provider ceiling reached", review.limitations)
        self.assertTrue(any("2 membership" in item for item in review.limitations))


if __name__ == "__main__":
    unittest.main()
