"""Tests for asset/service inventory projection into the identity graph."""

import unittest

from nightrecon.asset_inventory import AssetInventory, AssetRecord, AssetServiceRecord
from nightrecon.graph_builder import GraphBuildLimits
from nightrecon.graph_models import GraphEvidenceState, GraphNodeKind
from nightrecon.software_identity import SoftwareIdentity
from nightrecon.vulnerability_intelligence import (
    ServiceVulnerabilityResult,
    VulnerabilityFinding,
    VulnerabilityLookupResult,
)
from nightrecon.graph_projection import (
    add_vulnerability_evidence_to_identity_graph,
    build_identity_graph_from_asset_inventory,
)


class GraphProjectionTests(unittest.TestCase):
    def test_projects_asset_and_service_with_observed_relationship(self):
        inventory = AssetInventory(
            assets=(
                AssetRecord(
                    address="192.0.2.10",
                    first_seen="2026-09-27T10:00:00+00:00",
                    last_seen="2026-09-27T11:00:00+00:00",
                    last_checked_at="2026-09-27T11:00:00+00:00",
                    hostnames=("host.example.test",),
                    os_platform="Ubuntu",
                    os_family="Linux",
                    os_confidence="high",
                    os_evidence_count=2,
                    last_discovery_responsive=True,
                    discovery_methods=("tcp-connect",),
                    services=(
                        AssetServiceRecord(
                            port=443,
                            service="https",
                            product="nginx",
                            version="1.24.0",
                            protocol_version="HTTP/1.1",
                            platform="Ubuntu",
                            fingerprint_source="http-server",
                            fingerprint_confidence="high",
                            tls_certificate_sha256="abc123",
                        ),
                    ),
                    source_session_ids=("scan-2", "scan-1"),
                ),
            ),
            updated_at="2026-09-27T11:00:00+00:00",
        )

        graph = build_identity_graph_from_asset_inventory(inventory)

        self.assertEqual(len(graph.nodes), 2)
        self.assertEqual(len(graph.edges), 1)

        asset = next(node for node in graph.nodes if node.kind is GraphNodeKind.ASSET)
        service = next(
            node for node in graph.nodes if node.kind is GraphNodeKind.SERVICE
        )
        edge = graph.edges[0]

        self.assertEqual(asset.natural_key, "192.0.2.10")
        self.assertEqual(
            dict(asset.properties)["hostnames"],
            "host.example.test",
        )
        self.assertEqual(dict(asset.properties)["os_platform"], "Ubuntu")
        self.assertEqual(service.natural_key, "192.0.2.10:443/tcp")
        self.assertEqual(dict(service.properties)["product"], "nginx")
        self.assertEqual(dict(service.properties)["version"], "1.24.0")
        self.assertEqual(edge.relationship, "exposes")
        self.assertEqual(edge.evidence_state, GraphEvidenceState.OBSERVED)
        self.assertEqual(edge.source_node_id, asset.node_id)
        self.assertEqual(edge.target_node_id, service.node_id)
        self.assertEqual(
            tuple(item.source_id for item in asset.provenance),
            ("scan-1", "scan-2"),
        )

    def test_projection_is_deterministic_across_inventory_order(self):
        first_asset = AssetRecord(
            address="192.0.2.20",
            first_seen="2026-09-27T10:00:00+00:00",
            last_seen="2026-09-27T10:00:00+00:00",
            last_checked_at="2026-09-27T10:00:00+00:00",
            source_session_ids=("scan-b",),
        )
        second_asset = AssetRecord(
            address="192.0.2.10",
            first_seen="2026-09-27T09:00:00+00:00",
            last_seen="2026-09-27T09:00:00+00:00",
            last_checked_at="2026-09-27T09:00:00+00:00",
            services=(
                AssetServiceRecord(port=22, service="ssh"),
            ),
            source_session_ids=("scan-a",),
        )

        first = build_identity_graph_from_asset_inventory(
            AssetInventory(assets=(first_asset, second_asset))
        )
        second = build_identity_graph_from_asset_inventory(
            AssetInventory(assets=(second_asset, first_asset))
        )

        self.assertEqual(first, second)

    def test_empty_source_sessions_receive_non_secret_fallback_provenance(self):
        inventory = AssetInventory(
            assets=(
                AssetRecord(
                    address="192.0.2.30",
                    first_seen="2026-09-27T08:00:00+00:00",
                    last_seen="2026-09-27T08:00:00+00:00",
                    last_checked_at="2026-09-27T08:00:00+00:00",
                ),
            ),
        )

        graph = build_identity_graph_from_asset_inventory(inventory)

        self.assertEqual(
            graph.nodes[0].provenance[0].source_id,
            "asset:192.0.2.30",
        )

    def test_projection_respects_graph_limits(self):
        inventory = AssetInventory(
            assets=(
                AssetRecord(
                    address="192.0.2.40",
                    first_seen="2026-09-27T08:00:00+00:00",
                    last_seen="2026-09-27T08:00:00+00:00",
                    last_checked_at="2026-09-27T08:00:00+00:00",
                    services=(
                        AssetServiceRecord(port=80, service="http"),
                    ),
                    source_session_ids=("scan-limit",),
                ),
            ),
        )

        with self.assertRaisesRegex(ValueError, "node limit exceeded"):
            build_identity_graph_from_asset_inventory(
                inventory,
                limits=GraphBuildLimits(max_nodes=1, max_edges=1),
            )


    def test_vulnerability_matches_create_observed_graph_evidence_only(self):
        inventory = AssetInventory(
            assets=(
                AssetRecord(
                    address="192.0.2.50",
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
                    source_session_ids=("scan-vuln",),
                ),
            ),
        )
        graph = build_identity_graph_from_asset_inventory(inventory)
        software = SoftwareIdentity(
            product="nginx",
            version="1.24.0",
            source="http-server",
            evidence="nginx/1.24.0",
        )
        finding = VulnerabilityFinding(
            vulnerability_id="CVE-2026-1234",
            source="nvd",
            summary="Provider vulnerability description.",
            severity="HIGH",
            cvss_score=8.1,
            match_basis="cpe-match",
            matched_identifier="cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*",
        )
        results = (
            ServiceVulnerabilityResult(
                address="192.0.2.50",
                port=443,
                service="https",
                lookup=VulnerabilityLookupResult(
                    provider="nvd",
                    software_identity=software,
                    findings=(finding,),
                ),
            ),
        )

        enriched = add_vulnerability_evidence_to_identity_graph(
            graph,
            results,
            observed_at="2026-09-27T12:00:00+00:00",
        )

        vulnerability = next(
            node
            for node in enriched.nodes
            if node.kind is GraphNodeKind.VULNERABILITY
        )
        edge = next(
            edge
            for edge in enriched.edges
            if edge.relationship == "matched-vulnerability"
        )

        self.assertEqual(vulnerability.label, "CVE-2026-1234")
        self.assertEqual(dict(vulnerability.properties)["provider"], "nvd")
        self.assertEqual(dict(vulnerability.properties)["severity"], "HIGH")
        self.assertEqual(dict(vulnerability.properties)["cvss_score"], "8.1")
        self.assertEqual(edge.evidence_state, GraphEvidenceState.OBSERVED)
        self.assertEqual(
            dict(edge.properties)["claim"],
            "provider-match-only",
        )

    def test_vulnerability_provider_errors_do_not_create_findings(self):
        inventory = AssetInventory(
            assets=(
                AssetRecord(
                    address="192.0.2.51",
                    first_seen="2026-09-27T12:00:00+00:00",
                    last_seen="2026-09-27T12:00:00+00:00",
                    last_checked_at="2026-09-27T12:00:00+00:00",
                    services=(AssetServiceRecord(port=22, service="ssh"),),
                    source_session_ids=("scan-error",),
                ),
            ),
        )
        graph = build_identity_graph_from_asset_inventory(inventory)
        software = SoftwareIdentity(
            product="OpenSSH",
            version="9.6",
            source="ssh-banner",
            evidence="OpenSSH_9.6",
        )
        results = (
            ServiceVulnerabilityResult(
                address="192.0.2.51",
                port=22,
                service="ssh",
                lookup=VulnerabilityLookupResult(
                    provider="nvd",
                    software_identity=software,
                    error="provider unavailable",
                ),
            ),
        )

        enriched = add_vulnerability_evidence_to_identity_graph(
            graph,
            results,
        )

        self.assertEqual(enriched, graph)

    def test_vulnerability_projection_requires_existing_service_node(self):
        software = SoftwareIdentity(
            product="nginx",
            version="1.24.0",
            source="http-server",
            evidence="nginx/1.24.0",
        )
        results = (
            ServiceVulnerabilityResult(
                address="192.0.2.99",
                port=443,
                service="https",
                lookup=VulnerabilityLookupResult(
                    provider="nvd",
                    software_identity=software,
                    findings=(
                        VulnerabilityFinding(
                            vulnerability_id="CVE-2026-9999",
                            source="nvd",
                            summary="Example.",
                        ),
                    ),
                ),
            ),
        )

        with self.assertRaisesRegex(
            ValueError,
            "service is missing from graph",
        ):
            add_vulnerability_evidence_to_identity_graph(
                build_identity_graph_from_asset_inventory(
                    AssetInventory.empty()
                ),
                results,
            )


if __name__ == "__main__":
    unittest.main()
