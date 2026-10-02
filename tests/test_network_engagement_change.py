"""Tests for engagement-wide network change synthesis."""

import unittest

from nightrecon_red_engine.network_assessment_intelligence import (
    NetworkAssessmentIntelligence,
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


class NetworkEngagementDeltaTests(unittest.TestCase):
    def test_rollup_summarizes_changed_hosts_and_categories(self):
        first = compare_network_assessments(
            assessment(categories=("web-services",)),
            assessment(
                categories=("web-services", "remote-administration"),
            ),
        )
        second = compare_network_assessments(
            assessment(categories=("web-services",)),
            assessment(categories=("web-services",)),
        )

        result = build_network_engagement_delta(
            (
                HostNetworkDelta("host-a", first),
                HostNetworkDelta("host-b", second),
            )
        )

        self.assertEqual(result.hosts_compared, 2)
        self.assertEqual(result.hosts_changed, ("host-a",))
        self.assertIn(
            ("remote-administration", 1),
            result.added_exposure_categories,
        )

    def test_new_coverage_gap_hosts_are_visible(self):
        delta = compare_network_assessments(
            assessment(),
            assessment(gaps=("new gap",)),
        )

        result = build_network_engagement_delta(
            (HostNetworkDelta("host-a", delta),)
        )

        self.assertEqual(result.new_coverage_gap_hosts, ("host-a",))

    def test_duplicate_hosts_fail_closed(self):
        delta = compare_network_assessments(assessment(), assessment())

        with self.assertRaisesRegex(ValueError, "Duplicate host delta"):
            build_network_engagement_delta(
                (
                    HostNetworkDelta("host-a", delta),
                    HostNetworkDelta("host-a", delta),
                )
            )

    def test_no_deltas_is_explicit(self):
        result = build_network_engagement_delta(())

        self.assertEqual(result.hosts_compared, 0)
        self.assertIn("No network assessment comparisons", result.headline)


if __name__ == "__main__":
    unittest.main()
