"""No-network fixture benchmark regression tests."""
import copy
import unittest

from nightrecon_red_engine.offline_review_fixture_benchmark import benchmark_static_review
from nightrecon_red_engine.static_evidence_operator_review import StaticReviewError

A = "a" * 64
B = "b" * 64
C = "c" * 64


def review(ids=(A,)):
    return {
        "schema": "red.static_evidence_review.v1",
        "authority": "review_only_not_authorization",
        "cross_tool_correlations": [],
        "review_group_count": len(ids),
        "observation_count": len(ids),
        "review_groups": [
            {"review_id": i, "source_tool": "Trivy", "status": "needs_operator_review",
             "exploitability": "not_established", "observation_count": 1}
            for i in ids
        ],
    }


class OfflineBenchmarkTests(unittest.TestCase):
    def test_known_positive_negative_and_missed_fixture(self):
        result = benchmark_static_review(review((A, B)), expected_positive_ids=frozenset((A, C)),
                                         expected_negative_ids=frozenset((B,)))
        self.assertEqual((result["true_positive"], result["false_positive"], result["false_negative"]), (1, 1, 1))
        self.assertEqual(result["precision"], 0.5)
        self.assertEqual(result["recall"], 0.5)
        self.assertEqual(result["scope"], "synthetic_fixture_only")

    def test_unknown_predictions_never_assumed_false_positive(self):
        result = benchmark_static_review(review((A, C)), expected_positive_ids=frozenset((A,)),
                                         expected_negative_ids=frozenset((B,)))
        self.assertEqual(result["unlabeled_predictions"], 1)
        self.assertEqual(result["false_positive"], 0)
        self.assertIsNone(result["precision"])
        self.assertEqual(result["recall"], 1.0)

    def test_undefined_denominators_are_not_fabricated(self):
        result = benchmark_static_review(review(()), expected_positive_ids=frozenset(),
                                         expected_negative_ids=frozenset((B,)))
        self.assertIsNone(result["precision"])
        self.assertIsNone(result["recall"])

    def test_invalid_authority_claims_counts_and_labels_fail_closed(self):
        for mutate in (
            lambda r: r.update(authority="authorized"),
            lambda r: r.update(cross_tool_correlations=[{"claim": "linked"}]),
            lambda r: r.update(observation_count=2),
            lambda r: r["review_groups"][0].update(exploitability="confirmed"),
            lambda r: r["review_groups"][0].update(review_id="bad"),
        ):
            fixture = copy.deepcopy(review())
            mutate(fixture)
            with self.assertRaises(StaticReviewError):
                benchmark_static_review(fixture, expected_positive_ids=frozenset((A,)),
                                        expected_negative_ids=frozenset((B,)))
        with self.assertRaises(StaticReviewError):
            benchmark_static_review(review(), expected_positive_ids=frozenset((A,)),
                                    expected_negative_ids=frozenset((A,)))
        with self.assertRaises(StaticReviewError):
            benchmark_static_review(review(), expected_positive_ids=frozenset((A,)),
                                    expected_negative_ids=frozenset((B,)), max_groups=0)


if __name__ == "__main__":
    unittest.main()
