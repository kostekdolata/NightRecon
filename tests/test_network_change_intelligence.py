"""Tests for high-level network assessment change intelligence."""

import unittest

from nightrecon_red_engine.network_assessment_intelligence import (
    NetworkAssessmentIntelligence,
)
from nightrecon_red_engine.network_change_intelligence import (
    compare_network_assessments,
)


def assessment(*, categories=(), confidence="high", gaps=()):
    return NetworkAssessmentIntelligence(
        headline="Network service exposure observed",
        overview="overview",
        notable_exposures=(),
        confidence=confidence,
        coverage_gaps=gaps,
        recommended_next_actions=(),
        evidence_summary=(),
        exposure_categories=categories,
    )


class NetworkAssessmentDeltaTests(unittest.TestCase):
    def test_delta_surfaces_new_and_removed_exposure_categories(self):
        previous = assessment(
            categories=("web-services", "infrastructure-services"),
            confidence="high",
        )
        current = assessment(
            categories=("web-services", "remote-administration"),
            confidence="moderate",
        )

        result = compare_network_assessments(previous, current)

        self.assertEqual(
            result.headline,
            "Network assessment change detected",
        )
        self.assertEqual(
            result.added_exposure_categories,
            ("remote-administration",),
        )
        self.assertEqual(
            result.removed_exposure_categories,
            ("infrastructure-services",),
        )
        self.assertIn("high to moderate", result.confidence_change)

    def test_delta_tracks_new_and_resolved_coverage_gaps(self):
        previous = assessment(gaps=("old gap",))
        current = assessment(gaps=("new gap",))

        result = compare_network_assessments(previous, current)

        self.assertEqual(result.new_coverage_gaps, ("new gap",))
        self.assertEqual(result.resolved_coverage_gaps, ("old gap",))
        self.assertTrue(result.recommended_next_actions)

    def test_unchanged_assessment_produces_stable_baseline_feedback(self):
        previous = assessment(categories=("web-services",))
        current = assessment(categories=("web-services",))

        result = compare_network_assessments(previous, current)

        self.assertEqual(
            result.headline,
            "No material high-level network assessment change detected",
        )
        self.assertEqual(result.added_exposure_categories, ())
        self.assertEqual(result.removed_exposure_categories, ())
        self.assertIn("remains high", result.confidence_change)

    def test_delta_output_contains_no_risk_score(self):
        result = compare_network_assessments(
            assessment(),
            assessment(categories=("data-services",)),
        )

        self.assertNotIn("risk_score", str(result.to_dict()).lower())


if __name__ == "__main__":
    unittest.main()
