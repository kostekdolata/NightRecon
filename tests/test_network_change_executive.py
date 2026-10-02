"""Tests for executive engagement change summaries."""

import unittest

from nightrecon_red_engine.network_assessment_intelligence import (
    NetworkAssessmentIntelligence,
)
from nightrecon_red_engine.network_change_executive import (
    build_network_change_executive,
)
from nightrecon_red_engine.network_change_intelligence import (
    compare_network_assessments,
)
from nightrecon_red_engine.network_engagement_change import (
    HostNetworkDelta,
    build_network_engagement_delta,
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


class NetworkChangeExecutiveTests(unittest.TestCase):
    def test_change_summary_surfaces_new_themes_and_regressions(self):
        delta = compare_network_assessments(
            assessment(categories=("web-services",)),
            assessment(
                categories=("web-services", "remote-administration"),
                gaps=("new gap",),
            ),
        )
        engagement = build_network_engagement_delta(
            (HostNetworkDelta("host-a", delta),)
        )

        result = build_network_change_executive(engagement)

        self.assertEqual(
            result.headline,
            "Engagement network posture changed",
        )
        self.assertIn("host-a", result.changed_hosts)
        self.assertTrue(any(
            "remote-administration" in item
            for item in result.newly_observed_themes
        ))
        self.assertEqual(
            result.evidence_regressions,
            ("New coverage gap(s) on host-a",),
        )

    def test_unchanged_engagement_remains_neutral(self):
        delta = compare_network_assessments(
            assessment(categories=("web-services",)),
            assessment(categories=("web-services",)),
        )
        engagement = build_network_engagement_delta(
            (HostNetworkDelta("host-a", delta),)
        )

        result = build_network_change_executive(engagement)

        self.assertEqual(
            result.headline,
            "No material engagement network change detected",
        )
        self.assertFalse(result.changed_hosts)


if __name__ == "__main__":
    unittest.main()
