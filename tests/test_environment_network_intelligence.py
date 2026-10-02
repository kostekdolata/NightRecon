"""Tests for environment-wide Red Night network intelligence."""

import unittest

from nightrecon_red_engine.environment_network_intelligence import (
    ENVIRONMENT_NETWORK_INTERPRETATION,
    HostNetworkAssessment,
    build_environment_network_intelligence,
)
from nightrecon_red_engine.network_assessment_intelligence import (
    NetworkAssessmentIntelligence,
)


def host_assessment(
    *,
    headline="Network service exposure observed",
    categories=(),
    confidence="high",
    gaps=(),
    actions=(),
):
    return NetworkAssessmentIntelligence(
        headline=headline,
        overview="overview",
        notable_exposures=(),
        confidence=confidence,
        coverage_gaps=gaps,
        recommended_next_actions=actions,
        evidence_summary=(),
        exposure_categories=categories,
    )


class EnvironmentNetworkIntelligenceTests(unittest.TestCase):
    def test_environment_summary_highlights_broad_host_exposure(self):
        result = build_environment_network_intelligence(
            (
                HostNetworkAssessment(
                    "192.0.2.10",
                    host_assessment(
                        categories=(
                            "remote-administration",
                            "data-services",
                            "web-services",
                        ),
                        actions=("Review segmentation.",),
                    ),
                ),
                HostNetworkAssessment(
                    "192.0.2.20",
                    host_assessment(
                        categories=("web-services",),
                        confidence="moderate",
                        actions=("Review segmentation.",),
                    ),
                ),
            )
        )

        self.assertEqual(result.hosts_assessed, 2)
        self.assertEqual(
            result.headline,
            "Broad network exposure spans the assessed environment",
        )
        self.assertIn(
            ("web-services", 2),
            result.exposure_theme_counts,
        )
        self.assertTrue(any(
            host == "192.0.2.10"
            and "multiple exposure categories observed" in reasons
            for host, reasons in result.attention_hosts
        ))
        self.assertEqual(
            result.recommended_next_actions[0],
            "Review segmentation.",
        )

    def test_environment_summary_surfaces_shared_gaps(self):
        gap = (
            "1 UDP port(s) remain open|filtered because silence cannot "
            "distinguish filtering from an open service."
        )
        result = build_environment_network_intelligence(
            (
                HostNetworkAssessment(
                    "192.0.2.10",
                    host_assessment(
                        confidence="limited",
                        gaps=(gap,),
                    ),
                ),
                HostNetworkAssessment(
                    "192.0.2.20",
                    host_assessment(
                        confidence="limited",
                        gaps=(gap,),
                    ),
                ),
            )
        )

        self.assertIn(gap, result.shared_coverage_gaps)
        self.assertIn(("limited", 2), result.confidence_counts)
        self.assertEqual(
            result.interpretation,
            ENVIRONMENT_NETWORK_INTERPRETATION,
        )

    def test_duplicate_hosts_fail_closed(self):
        assessment = host_assessment()

        with self.assertRaisesRegex(
            ValueError,
            "Duplicate host assessment",
        ):
            build_environment_network_intelligence(
                (
                    HostNetworkAssessment("host-a", assessment),
                    HostNetworkAssessment("host-a", assessment),
                )
            )

    def test_empty_environment_is_explicitly_incomplete(self):
        result = build_environment_network_intelligence(())

        self.assertEqual(result.hosts_assessed, 0)
        self.assertEqual(
            result.headline,
            "No host network assessments available",
        )
        self.assertTrue(result.shared_coverage_gaps)
        self.assertIn(
            "cannot yet be characterized",
            result.overview,
        )

    def test_output_is_high_level_and_serializable(self):
        result = build_environment_network_intelligence(
            (
                HostNetworkAssessment(
                    "host-a",
                    host_assessment(
                        categories=("remote-administration",),
                    ),
                ),
            )
        )

        payload = result.to_dict()

        self.assertIn("attention_hosts", payload)
        self.assertIn("exposure_theme_counts", payload)
        self.assertNotIn("risk_score", str(payload).lower())
        self.assertNotIn("exploitability", payload["headline"].lower())


if __name__ == "__main__":
    unittest.main()
