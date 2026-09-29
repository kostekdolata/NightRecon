"""v0.43 Batch 6 reviewed ATT&CK relationship tests."""

from __future__ import annotations

import unittest

from nightrecon_red_engine.validation_attack_review import (
    ATTACK_REVIEW_INTERPRETATION,
    BUILTIN_VALIDATION_ATTACK_REVIEW_REGISTRY,
    ValidationAttackReview,
    ValidationAttackReviewRegistry,
    assert_attack_review_coverage,
)
from nightrecon_red_engine.validation_techniques import (
    BUILTIN_VALIDATION_TECHNIQUE_REGISTRY,
)


class ValidationAttackReviewTests(unittest.TestCase):
    def test_every_builtin_technique_has_one_reviewed_disposition(self):
        assert_attack_review_coverage()
        self.assertEqual(
            tuple(
                item.technique_id
                for item in BUILTIN_VALIDATION_ATTACK_REVIEW_REGISTRY.list()
            ),
            tuple(
                item.technique_id
                for item in BUILTIN_VALIDATION_TECHNIQUE_REGISTRY.list()
            ),
        )

    def test_tcp_proof_is_related_to_t1046_without_equivalence_claim(self):
        technique = BUILTIN_VALIDATION_TECHNIQUE_REGISTRY.get(
            "service.tcp-property-proof"
        )
        review = BUILTIN_VALIDATION_ATTACK_REVIEW_REGISTRY.get(
            technique.technique_id
        )

        self.assertEqual(technique.attack_ids, ("T1046",))
        self.assertEqual(review.disposition, "related")
        self.assertEqual(review.attack_ids, ("T1046",))
        self.assertEqual(review.references[0].name, "Network Service Discovery")
        self.assertEqual(review.references[0].tactic, "Discovery")
        self.assertEqual(review.references[0].version, "3.2")
        self.assertEqual(review.references[0].last_modified, "2026-05-12")
        self.assertFalse(review.to_dict()["equivalence_claim"])
        self.assertIn("does not mean", ATTACK_REVIEW_INTERPRETATION)

    def test_tls_and_http_proofs_are_explicitly_reviewed_unmapped(self):
        for technique_id in (
            "service.tls-property-proof",
            "web.http-policy-proof",
        ):
            with self.subTest(technique_id=technique_id):
                technique = BUILTIN_VALIDATION_TECHNIQUE_REGISTRY.get(
                    technique_id
                )
                review = BUILTIN_VALIDATION_ATTACK_REVIEW_REGISTRY.get(
                    technique_id
                )
                self.assertEqual(technique.attack_ids, ())
                self.assertEqual(review.disposition, "reviewed-unmapped")
                self.assertEqual(review.attack_ids, ())
                self.assertTrue(review.rationale)

    def test_related_review_requires_reference_and_unmapped_forbids_one(self):
        mapped = BUILTIN_VALIDATION_ATTACK_REVIEW_REGISTRY.get(
            "service.tcp-property-proof"
        )
        with self.assertRaisesRegex(ValueError, "require a reference"):
            ValidationAttackReview(
                technique_id="service.test-proof",
                disposition="related",
                references=(),
                rationale="Reviewed relation.",
                reviewed_at="2026-09-29",
            )
        with self.assertRaisesRegex(ValueError, "must not carry"):
            ValidationAttackReview(
                technique_id="service.test-proof",
                disposition="reviewed-unmapped",
                references=mapped.references,
                rationale="No exact mapping.",
                reviewed_at="2026-09-29",
            )

    def test_registry_rejects_duplicate_review(self):
        review = BUILTIN_VALIDATION_ATTACK_REVIEW_REGISTRY.get(
            "service.tcp-property-proof"
        )
        with self.assertRaisesRegex(ValueError, "unique per technique"):
            ValidationAttackReviewRegistry((review, review))


if __name__ == "__main__":
    unittest.main()
