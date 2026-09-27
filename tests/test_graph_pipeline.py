"""Tests for the deterministic NightRecon graph assembly pipeline."""

import unittest

from nightrecon.assessment_engine import (
    AssessmentExecutionResult,
    AssessmentFinding,
    ServiceAssessmentResult,
)
from nightrecon.asset_inventory import AssetInventory, AssetRecord, AssetServiceRecord
from nightrecon.graph_models import GraphNodeKind
from nightrecon.graph_pipeline import build_identity_graph
from nightrecon.software_identity import SoftwareIdentity
from nightrecon.threat_context import ThreatContextResult
from nightrecon.vulnerability_intelligence import (
    ServiceVulnerabilityResult,
    VulnerabilityFinding,
    VulnerabilityLookupResult,
)


class GraphPipelineTests(unittest.TestCase):
    def test_pipeline_composes_existing_evidence_in_one_snapshot(self):
        inventory = AssetInventory(
            assets=(
                AssetRecord(
                    address="192.0.2.70",
                    first_seen="2026-09-27T12:00:00+00:00",
                    last_seen="2026-09-27T12:00:00+00:00",
                    last_checked_at="2026-09-27T12:00:00+00:00",
                    services=(
                        AssetServiceRecord(
                            port=443,
                            service="https",
                            product="nginx",
                            version="1.24.0",
                        ),
                    ),
                    source_session_ids=("scan-pipeline",),
                ),
            ),
        )
        software = SoftwareIdentity(
            product="nginx",
            version="1.24.0",
            source="http-server",
            evidence="nginx/1.24.0",
        )
        vulnerabilities = (
            ServiceVulnerabilityResult(
                address="192.0.2.70",
                port=443,
                service="https",
                lookup=VulnerabilityLookupResult(
                    provider="nvd",
                    software_identity=software,
                    findings=(
                        VulnerabilityFinding(
                            vulnerability_id="CVE-2026-7000",
                            source="nvd",
                            summary="Example vulnerability.",
                            severity="HIGH",
                        ),
                    ),
                ),
            ),
        )
        threat_context = (
            ThreatContextResult(
                vulnerability_id="CVE-2026-7000",
                known_exploited=True,
                epss_probability=0.6,
                epss_percentile=0.95,
            ),
        )
        assessments = (
            ServiceAssessmentResult(
                address="192.0.2.70",
                port=443,
                service="https",
                executions=(
                    AssessmentExecutionResult(
                        check_id="web.headers",
                        status="completed",
                        findings=(
                            AssessmentFinding(
                                check_id="web.headers",
                                title="Missing security header",
                                summary="Observed header is absent.",
                            ),
                        ),
                    ),
                ),
            ),
        )

        graph = build_identity_graph(
            inventory=inventory,
            vulnerabilities=vulnerabilities,
            threat_context=threat_context,
            assessments=assessments,
            vulnerability_observed_at="2026-09-27T12:01:00+00:00",
            threat_context_observed_at="2026-09-27T12:02:00+00:00",
            assessment_observed_at="2026-09-27T12:03:00+00:00",
        )

        kinds = tuple(node.kind for node in graph.nodes)
        self.assertIn(GraphNodeKind.ASSET, kinds)
        self.assertIn(GraphNodeKind.SERVICE, kinds)
        self.assertIn(GraphNodeKind.VULNERABILITY, kinds)
        self.assertIn(GraphNodeKind.ASSESSMENT_FINDING, kinds)

        vulnerability = next(
            node
            for node in graph.nodes
            if node.kind is GraphNodeKind.VULNERABILITY
        )
        properties = dict(vulnerability.properties)
        self.assertEqual(properties["known_exploited"], "true")
        self.assertEqual(properties["epss_probability"], "0.6")

        relationships = tuple(edge.relationship for edge in graph.edges)
        self.assertIn("exposes", relationships)
        self.assertIn("matched-vulnerability", relationships)
        self.assertIn("has-assessment-finding", relationships)

    def test_pipeline_is_deterministic_for_identical_inputs(self):
        inventory = AssetInventory(
            assets=(
                AssetRecord(
                    address="192.0.2.71",
                    first_seen="2026-09-27T12:00:00+00:00",
                    last_seen="2026-09-27T12:00:00+00:00",
                    last_checked_at="2026-09-27T12:00:00+00:00",
                    services=(AssetServiceRecord(port=22, service="ssh"),),
                    source_session_ids=("scan-deterministic",),
                ),
            ),
        )

        first = build_identity_graph(inventory=inventory)
        second = build_identity_graph(inventory=inventory)

        self.assertEqual(first, second)

    def test_pipeline_validates_snapshot_before_returning(self):
        graph = build_identity_graph(
            inventory=AssetInventory(
                assets=(
                    AssetRecord(
                        address="192.0.2.72",
                        first_seen="2026-09-27T12:00:00+00:00",
                        last_seen="2026-09-27T12:00:00+00:00",
                        last_checked_at="2026-09-27T12:00:00+00:00",
                        services=(AssetServiceRecord(port=80, service="http"),),
                        source_session_ids=("scan-valid",),
                    ),
                ),
            )
        )

        self.assertEqual(len(graph.nodes), 2)
        self.assertEqual(len(graph.edges), 1)

    def test_pipeline_does_not_require_optional_evidence_sources(self):
        graph = build_identity_graph(inventory=AssetInventory.empty())

        self.assertEqual(graph.nodes, ())
        self.assertEqual(graph.edges, ())


if __name__ == "__main__":
    unittest.main()
