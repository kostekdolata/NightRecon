"""Tests for executive network assessment synthesis."""

import unittest

from nightrecon_red_engine.environment_network_intelligence import (
    ENVIRONMENT_NETWORK_INTERPRETATION,
)
from nightrecon_red_engine.network_context_intelligence import (
    NetworkContextIntelligence,
)
from nightrecon_red_engine.network_evidence_completeness import (
    NetworkEvidenceCompleteness,
)
from nightrecon_red_engine.network_executive_assessment import (
    build_network_executive_assessment,
)
from nightrecon_red_engine.network_operator_brief import NetworkOperatorBrief


class NetworkExecutiveAssessmentTests(unittest.TestCase):
    def test_executive_summary_combines_exposure_context_and_completeness(self):
        operator = NetworkOperatorBrief(
            executive_summary="Network exposure is present.",
            primary_focus_areas=("Web service exposure is present.",),
            hosts_for_review=("host-a",),
            confidence_statement="Assessment confidence is supported.",
            coverage_statement="Coverage is available.",
            next_actions=("Review web exposure.",),
            interpretation=ENVIRONMENT_NETWORK_INTERPRETATION,
        )
        context = NetworkContextIntelligence(
            headline="Network exposure has correlated security context",
            overview="Matched vulnerability context is available.",
            evidence_quality="high",
            notable_context=("1 high matched vulnerability finding.",),
            coverage_gaps=(),
            recommended_next_actions=("Review matched records.",),
        )
        completeness = NetworkEvidenceCompleteness(
            level="comprehensive",
            summary="All layers represented.",
            completed_layers=(
                "network-exposure",
                "service-identification",
                "vulnerability-intelligence",
                "threat-context",
            ),
            missing_layers=(),
            evidence_notes=(),
        )

        result = build_network_executive_assessment(
            operator_brief=operator,
            context=context,
            completeness=completeness,
        )

        self.assertEqual(
            result.headline,
            "Network exposure with correlated security context",
        )
        self.assertEqual(result.evidence_completeness, "comprehensive")
        self.assertIn("host-a", result.operator_focus)
        self.assertIn(
            "1 high matched vulnerability finding.",
            result.key_observations,
        )
        self.assertEqual(
            result.recommended_next_actions,
            ("Review web exposure.", "Review matched records."),
        )

    def test_missing_layers_become_limitations(self):
        operator = NetworkOperatorBrief(
            executive_summary="Network exposure is present.",
            primary_focus_areas=(),
            hosts_for_review=(),
            confidence_statement="Limited.",
            coverage_statement="Incomplete.",
            next_actions=(),
            interpretation=ENVIRONMENT_NETWORK_INTERPRETATION,
        )
        context = NetworkContextIntelligence(
            headline="No correlated security context confirmed",
            overview="No correlated context.",
            evidence_quality="limited",
            notable_context=(),
            coverage_gaps=("Threat context unavailable.",),
            recommended_next_actions=("Improve evidence.",),
        )
        completeness = NetworkEvidenceCompleteness(
            level="limited",
            summary="Limited evidence.",
            completed_layers=("network-exposure",),
            missing_layers=(
                "service-identification",
                "vulnerability-intelligence",
                "threat-context",
            ),
            evidence_notes=(),
        )

        result = build_network_executive_assessment(
            operator_brief=operator,
            context=context,
            completeness=completeness,
        )

        self.assertEqual(result.headline, "Network exposure assessment")
        self.assertTrue(any(
            "Missing evidence layers:" in item
            for item in result.limitations
        ))
        self.assertIn("Threat context unavailable.", result.limitations)
        self.assertNotIn("risk_score", str(result.to_dict()).lower())


if __name__ == "__main__":
    unittest.main()
