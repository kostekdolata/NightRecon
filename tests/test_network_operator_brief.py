"""Tests for concise high-level network operator briefs."""

import unittest

from nightrecon_red_engine.environment_network_intelligence import (
    EnvironmentNetworkIntelligence,
)
from nightrecon_red_engine.network_operator_brief import (
    build_network_operator_brief,
)


class NetworkOperatorBriefTests(unittest.TestCase):
    def test_brief_prioritizes_recurring_exposure_themes(self):
        intelligence = EnvironmentNetworkIntelligence(
            headline="Broad network exposure spans the assessed environment",
            overview="Multiple service categories are present.",
            hosts_assessed=4,
            exposure_theme_counts=(
                ("data-services", 2),
                ("remote-administration", 3),
                ("web-services", 4),
            ),
            confidence_counts=(
                ("high", 2),
                ("moderate", 1),
                ("limited", 1),
            ),
            attention_hosts=(
                ("host-a", ("remote administration exposure present",)),
                ("host-b", ("multiple exposure categories observed",)),
            ),
            shared_coverage_gaps=(
                "2 UDP port(s) remain open|filtered.",
            ),
            recommended_next_actions=(
                "Review segmentation.",
                "Review remote administration controls.",
            ),
        )

        brief = build_network_operator_brief(intelligence)

        self.assertEqual(
            brief.primary_focus_areas[0],
            "Web service exposure is present on 4 assessed host(s).",
        )
        self.assertEqual(
            brief.hosts_for_review,
            ("host-a", "host-b"),
        )
        self.assertIn("mixed", brief.confidence_statement)
        self.assertIn("open|filtered", brief.coverage_statement)

    def test_brief_is_bounded_for_operator_readability(self):
        intelligence = EnvironmentNetworkIntelligence(
            headline="Network exposure is present",
            overview="overview",
            hosts_assessed=10,
            exposure_theme_counts=tuple(
                (f"theme-{index}", 10 - index)
                for index in range(6)
            ),
            confidence_counts=(("high", 10),),
            attention_hosts=tuple(
                (f"host-{index}", ("reason",))
                for index in range(10)
            ),
            shared_coverage_gaps=(),
            recommended_next_actions=tuple(
                f"action-{index}" for index in range(10)
            ),
        )

        brief = build_network_operator_brief(
            intelligence,
            max_focus_areas=3,
            max_hosts=4,
            max_actions=2,
        )

        self.assertEqual(len(brief.primary_focus_areas), 3)
        self.assertEqual(len(brief.hosts_for_review), 4)
        self.assertEqual(len(brief.next_actions), 2)

    def test_no_host_evidence_is_explicitly_incomplete(self):
        intelligence = EnvironmentNetworkIntelligence(
            headline="No host network assessments available",
            overview="No host-level evidence.",
            hosts_assessed=0,
            exposure_theme_counts=(),
            confidence_counts=(),
            attention_hosts=(),
            shared_coverage_gaps=(
                "No host-level network assessment evidence is available.",
            ),
            recommended_next_actions=(
                "Complete bounded host/network assessment coverage.",
            ),
        )

        brief = build_network_operator_brief(intelligence)

        self.assertIn(
            "Confidence cannot be characterized",
            brief.confidence_statement,
        )
        self.assertIn(
            "No recurring responsive network exposure theme",
            brief.primary_focus_areas[0],
        )

    def test_brief_has_no_numeric_risk_score(self):
        intelligence = EnvironmentNetworkIntelligence(
            headline="Network exposure is present",
            overview="overview",
            hosts_assessed=1,
            exposure_theme_counts=(("remote-administration", 1),),
            confidence_counts=(("high", 1),),
            attention_hosts=(("host-a", ("reason",)),),
            shared_coverage_gaps=(),
            recommended_next_actions=("Review access controls.",),
        )

        payload = build_network_operator_brief(intelligence).to_dict()

        self.assertNotIn("risk_score", str(payload).lower())
        self.assertNotIn("exploitability", payload["executive_summary"].lower())


if __name__ == "__main__":
    unittest.main()
