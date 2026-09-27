"""Tests for assessment-finding graph integration."""

import unittest

from nightrecon.assessment_engine import (
    AssessmentExecutionResult,
    AssessmentFinding,
    ServiceAssessmentResult,
)
from nightrecon.asset_inventory import AssetInventory, AssetRecord, AssetServiceRecord
from nightrecon.graph_assessment import add_assessment_findings_to_identity_graph
from nightrecon.graph_models import GraphEvidenceState, GraphNodeKind
from nightrecon.graph_projection import build_identity_graph_from_asset_inventory


class GraphAssessmentTests(unittest.TestCase):
    def build_graph(self):
        return build_identity_graph_from_asset_inventory(
            AssetInventory(
                assets=(
                    AssetRecord(
                        address="192.0.2.60",
                        first_seen="2026-09-27T12:00:00+00:00",
                        last_seen="2026-09-27T12:00:00+00:00",
                        last_checked_at="2026-09-27T12:00:00+00:00",
                        services=(
                            AssetServiceRecord(port=443, service="https"),
                        ),
                        source_session_ids=("scan-assessment",),
                    ),
                ),
            )
        )

    def test_completed_findings_become_observed_graph_evidence(self):
        finding = AssessmentFinding(
            check_id="web.headers",
            title="Missing security header",
            summary="Observed header is absent.",
            evidence=("header=content-security-policy",),
            severity="medium",
            remediation="Add the header.",
        )
        assessments = (
            ServiceAssessmentResult(
                address="192.0.2.60",
                port=443,
                service="https",
                executions=(
                    AssessmentExecutionResult(
                        check_id="web.headers",
                        status="completed",
                        findings=(finding,),
                        check_source="builtin",
                        check_source_version="1",
                    ),
                ),
            ),
        )

        enriched = add_assessment_findings_to_identity_graph(
            self.build_graph(),
            assessments,
            observed_at="2026-09-27T17:30:00+00:00",
        )

        finding_node = next(
            node
            for node in enriched.nodes
            if node.kind is GraphNodeKind.ASSESSMENT_FINDING
        )
        edge = next(
            edge
            for edge in enriched.edges
            if edge.relationship == "has-assessment-finding"
        )

        self.assertEqual(finding_node.label, "Missing security header")
        self.assertEqual(
            dict(finding_node.properties)["check_id"],
            "web.headers",
        )
        self.assertEqual(
            dict(finding_node.properties)["severity"],
            "medium",
        )
        self.assertEqual(edge.evidence_state, GraphEvidenceState.OBSERVED)

    def test_skipped_and_errored_executions_do_not_create_findings(self):
        assessments = (
            ServiceAssessmentResult(
                address="192.0.2.60",
                port=443,
                service="https",
                executions=(
                    AssessmentExecutionResult(
                        check_id="one",
                        status="skipped",
                        reason="not_applicable",
                    ),
                    AssessmentExecutionResult(
                        check_id="two",
                        status="error",
                        error="failed",
                    ),
                ),
            ),
        )

        graph = self.build_graph()
        enriched = add_assessment_findings_to_identity_graph(
            graph,
            assessments,
        )

        self.assertEqual(enriched, graph)

    def test_missing_service_fails_closed(self):
        assessments = (
            ServiceAssessmentResult(
                address="192.0.2.99",
                port=80,
                service="http",
                executions=(),
            ),
        )

        with self.assertRaisesRegex(
            ValueError,
            "service is missing from graph",
        ):
            add_assessment_findings_to_identity_graph(
                self.build_graph(),
                assessments,
            )


if __name__ == "__main__":
    unittest.main()
