"""Tests for the deterministic NightRecon graph assembly pipeline."""

import unittest

from nightrecon.assessment_engine import (
    AssessmentExecutionResult,
    AssessmentFinding,
    ServiceAssessmentResult,
)
from nightrecon.asset_inventory import AssetInventory, AssetRecord, AssetServiceRecord
from nightrecon.graph_critical_asset import CriticalAssetEvidence
from nightrecon.graph_identity_evidence import (
    GroupEvidence,
    GroupMembershipEvidence,
    IdentityEvidence,
    IdentityEvidenceBundle,
    PermissionEvidence,
)
from nightrecon.graph_models import GraphEvidenceState, GraphNodeKind
from nightrecon.graph_pipeline import (
    build_correlated_identity_graph,
    build_identity_graph,
)
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

    def test_pipeline_composes_identity_group_and_permission_evidence(self):
        inventory = AssetInventory(
            assets=(
                AssetRecord(
                    address="192.0.2.73",
                    first_seen="2026-09-27T19:00:00+00:00",
                    last_seen="2026-09-27T19:00:00+00:00",
                    last_checked_at="2026-09-27T19:00:00+00:00",
                    services=(AssetServiceRecord(port=443, service="https"),),
                    source_session_ids=("scan-identity",),
                ),
            ),
        )
        identity_evidence = IdentityEvidenceBundle(
            identities=(
                IdentityEvidence(
                    natural_key="user:alice",
                    label="Alice",
                    source_id="identity-alice",
                    identity_type="user",
                ),
            ),
            groups=(
                GroupEvidence(
                    natural_key="group:admins",
                    label="Admins",
                    source_id="group-admins",
                ),
            ),
            memberships=(
                GroupMembershipEvidence(
                    member_kind=GraphNodeKind.IDENTITY,
                    member_key="user:alice",
                    group_key="group:admins",
                    source_id="membership-alice-admins",
                    evidence_state=GraphEvidenceState.INFERRED,
                ),
            ),
            permissions=(
                PermissionEvidence(
                    natural_key="permission:admins-asset",
                    label="Administrative access",
                    subject_kind=GraphNodeKind.GROUP,
                    subject_key="group:admins",
                    target_kind=GraphNodeKind.ASSET,
                    target_key="192.0.2.73",
                    source_id="permission-admins-asset",
                ),
            ),
        )

        graph = build_identity_graph(
            inventory=inventory,
            identity_evidence=identity_evidence,
            identity_observed_at="2026-09-27T19:01:00+00:00",
        )

        kinds = {node.kind for node in graph.nodes}
        self.assertIn(GraphNodeKind.IDENTITY, kinds)
        self.assertIn(GraphNodeKind.GROUP, kinds)
        self.assertIn(GraphNodeKind.PERMISSION, kinds)
        relationships = {edge.relationship for edge in graph.edges}
        self.assertTrue(
            {"member-of", "has-permission", "applies-to"}.issubset(
                relationships
            )
        )

    def test_correlated_pipeline_links_exact_ad_hostname_to_network_asset(self):
        inventory = AssetInventory(
            assets=(
                AssetRecord(
                    address="192.0.2.75",
                    first_seen="2026-09-29T03:00:00+00:00",
                    last_seen="2026-09-29T03:00:00+00:00",
                    last_checked_at="2026-09-29T03:00:00+00:00",
                    hostnames=("app.example.test",),
                    source_session_ids=("scan-correlation",),
                ),
            ),
        )
        identity_evidence = IdentityEvidenceBundle(
            identities=(
                IdentityEvidence(
                    natural_key="ad:computer:opaque",
                    label="APP01",
                    source_id="ad-correlation",
                    identity_type="ad-computer",
                    properties=(("dns_hostname", "app.example.test"),),
                ),
            ),
        )

        result = build_correlated_identity_graph(
            inventory=inventory,
            identity_evidence=identity_evidence,
        )

        self.assertEqual(result.unresolved, ())
        self.assertEqual(len(result.correlated_edge_ids), 1)
        edge = next(
            item for item in result.graph.edges
            if item.edge_id in result.correlated_edge_ids
        )
        self.assertEqual(edge.relationship, "correlates-to")
        self.assertIs(edge.evidence_state, GraphEvidenceState.INFERRED)

    def test_pipeline_projects_critical_asset_evidence(self):
        inventory = AssetInventory(
            assets=(
                AssetRecord(
                    address="192.0.2.74",
                    first_seen="2026-09-27T19:00:00+00:00",
                    last_seen="2026-09-27T19:00:00+00:00",
                    last_checked_at="2026-09-27T19:00:00+00:00",
                    source_session_ids=("scan-critical",),
                ),
            ),
        )

        graph = build_identity_graph(
            inventory=inventory,
            critical_assets=(
                CriticalAssetEvidence(
                    asset_key="192.0.2.74",
                    label="Tier 0 server",
                    source_id="critical-tier0",
                    rationale="Tier 0 administration dependency.",
                ),
            ),
            critical_asset_observed_at="2026-09-27T19:02:00+00:00",
        )

        self.assertTrue(
            any(
                node.kind is GraphNodeKind.CRITICAL_ASSET
                for node in graph.nodes
            )
        )
        self.assertIn(
            "classified-as-critical",
            {edge.relationship for edge in graph.edges},
        )

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
