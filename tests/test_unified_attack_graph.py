"""Unified attack graph must be evidence-backed and fail soft on missing entities."""

from __future__ import annotations

import unittest

from nightrecon_red_engine.graph_models import GraphEvidenceState, GraphNodeKind
from nightrecon_red_engine.unified_attack_graph import (
    build_correlated_unified_attack_graph,
    build_unified_attack_graph,
    explain_edge,
)
from nightrecon_shared_core.contracts import EvidenceRecord


def record(evidence_id, evidence_type, data):
    return EvidenceRecord(
        engagement_id="eng-graph",
        evidence_id=evidence_id,
        source_night="red",
        evidence_type=evidence_type,
        observed_at="2026-09-28T12:00:00+00:00",
        provenance=f"fixture://{evidence_id}",
        data=data,
    )


class UnifiedAttackGraphTests(unittest.TestCase):
    def test_assets_identities_findings_and_critical_assets_share_one_graph(self):
        records = (
            record("asset-1", "asset.observation", {
                "asset_key": "10.0.0.10", "label": "App Server",
            }),
            record("identity-1", "identity.observation", {
                "identity_key": "user:alice", "label": "Alice",
            }),
            record("access-1", "graph.relationship", {
                "source_kind": "identity", "source_key": "user:alice",
                "target_kind": "asset", "target_key": "10.0.0.10",
                "relationship": "authenticated-access",
                "evidence_state": "observed",
            }),
            record("vuln-1", "vulnerability.observation", {
                "asset_key": "10.0.0.10", "vulnerability_id": "CVE-TEST-1",
                "label": "Test vulnerability",
            }),
            record("critical-1", "critical-asset.observation", {
                "asset_key": "10.0.0.10", "critical_key": "finance-app",
                "label": "Finance Application",
            }),
        )
        result = build_unified_attack_graph(records)
        self.assertEqual(result.unresolved_records, ())
        self.assertEqual(len(result.graph.nodes), 4)
        self.assertEqual(len(result.graph.edges), 3)
        self.assertEqual(
            {node.kind for node in result.graph.nodes},
            {
                GraphNodeKind.ASSET, GraphNodeKind.IDENTITY,
                GraphNodeKind.VULNERABILITY, GraphNodeKind.CRITICAL_ASSET,
            },
        )
        self.assertTrue(all(
            edge.provenance[0].source_type == "engagement-evidence"
            for edge in result.graph.edges
        ))

    def test_portable_graph_preserves_properties_for_exact_correlation(self):
        records = (
            record("asset-1", "asset.observation", {
                "asset_key": "10.0.0.10",
                "label": "App Server",
                "properties": {"hostnames": "app.example.test"},
            }),
            record("identity-1", "identity.observation", {
                "identity_key": "ad:computer:opaque",
                "label": "APP01",
                "properties": {"dns_hostname": "app.example.test"},
            }),
        )

        result = build_correlated_unified_attack_graph(records)

        self.assertEqual(result.unresolved_records, ())
        self.assertEqual(result.unresolved_correlations, ())
        self.assertEqual(len(result.correlated_edge_ids), 1)
        identity = next(
            node for node in result.graph.nodes
            if node.kind is GraphNodeKind.IDENTITY
        )
        self.assertEqual(
            dict(identity.properties)["dns_hostname"],
            "app.example.test",
        )
        edge = next(
            item for item in result.graph.edges
            if item.edge_id in result.correlated_edge_ids
        )
        self.assertEqual(edge.relationship, "correlates-to")
        self.assertIs(edge.evidence_state, GraphEvidenceState.INFERRED)

    def test_portable_web_surface_correlates_to_exact_network_service(self):
        records = (
            record("asset-web", "asset.observation", {
                "asset_key": "10.0.0.20",
                "label": "Web Host",
                "properties": {
                    "address": "10.0.0.20",
                    "hostnames": "web.example.test",
                },
            }),
            record("network-service", "service.observation", {
                "service_key": "10.0.0.20:443/tcp",
                "label": "https",
                "properties": {
                    "address": "10.0.0.20",
                    "port": "443",
                    "protocol": "tcp",
                },
            }),
            record("web-surface", "service.observation", {
                "service_key": "web-surface:web:opaque",
                "label": "https://web.example.test",
                "properties": {
                    "origin_host": "web.example.test",
                    "origin_port": "443",
                    "origin_scheme": "https",
                    "surface_type": "web",
                },
            }),
        )

        result = build_correlated_unified_attack_graph(records)

        self.assertEqual(result.unresolved_records, ())
        self.assertEqual(result.unresolved_correlations, ())
        self.assertEqual(len(result.correlated_edge_ids), 1)
        edge = next(
            item for item in result.graph.edges
            if item.edge_id in result.correlated_edge_ids
        )
        source = next(
            node for node in result.graph.nodes
            if node.node_id == edge.source_node_id
        )
        target = next(
            node for node in result.graph.nodes
            if node.node_id == edge.target_node_id
        )
        self.assertEqual(source.natural_key, "10.0.0.20:443/tcp")
        self.assertEqual(target.natural_key, "web-surface:web:opaque")
        self.assertEqual(
            dict(edge.properties)["correlation_basis"],
            "exact-origin-host-port",
        )


    def test_portable_cloud_correlates_to_network_and_entra_identity(self):
        records = (
            record("network", "asset.observation", {
                "asset_key": "10.0.0.60",
                "label": "Observed VM",
                "properties": {
                    "address": "10.0.0.60",
                    "hostnames": "vm60.example.test",
                },
            }),
            record("cloud-resource", "asset.observation", {
                "asset_key": "cloud:azure:resource:vm-60",
                "label": "Azure VM",
                "properties": {
                    "cloud_provider": "azure",
                    "cloud_resource_id": "vm-60",
                    "cloud_resource_kind": "virtual-machine",
                    "private_ip": "10.0.0.60",
                    "hostname": "vm60.example.test",
                },
            }),
            record("entra-live", "identity.observation", {
                "identity_key": "entra:user:opaque-60",
                "label": "Cloud User",
                "properties": {
                    "entra_tenant_id": "tenant-60",
                    "entra_object_id": "object-60",
                },
            }),
            record("cloud-identity", "identity.observation", {
                "identity_key": "cloud:entra:identity:object-60",
                "label": "Cloud User",
                "properties": {
                    "cloud_provider": "entra",
                    "cloud_identity_id": "object-60",
                    "entra_tenant_id": "tenant-60",
                    "entra_object_id": "object-60",
                },
            }),
        )

        result = build_correlated_unified_attack_graph(records)

        self.assertEqual(result.unresolved_records, ())
        self.assertEqual(result.unresolved_correlations, ())
        self.assertEqual(len(result.correlated_edge_ids), 2)
        bases = {
            dict(edge.properties)["correlation_basis"]
            for edge in result.graph.edges
            if edge.edge_id in result.correlated_edge_ids
        }
        self.assertEqual(
            bases,
            {"exact-cloud-network-key", "exact-cloud-entra-object"},
        )

    def test_missing_endpoint_stays_unresolved_without_fabricated_edge(self):
        result = build_unified_attack_graph((
            record("rel-1", "graph.relationship", {
                "source_kind": "identity", "source_key": "missing-user",
                "target_kind": "asset", "target_key": "missing-asset",
                "relationship": "access",
            }),
        ))
        self.assertEqual(result.unresolved_records, ("rel-1",))
        self.assertEqual(result.graph.nodes, ())
        self.assertEqual(result.graph.edges, ())

    def test_explicit_inference_remains_labeled_inferred(self):
        result = build_unified_attack_graph((
            record("asset-1", "asset.observation", {
                "asset_key": "10.0.0.10", "label": "App",
            }),
            record("identity-1", "identity.observation", {
                "identity_key": "user:alice", "label": "Alice",
            }),
            record("rel-1", "graph.relationship", {
                "source_kind": "identity", "source_key": "user:alice",
                "target_kind": "asset", "target_key": "10.0.0.10",
                "relationship": "possible-access",
                "evidence_state": "inferred",
            }),
        ))
        edge = result.graph.edges[0]
        self.assertIs(edge.evidence_state, GraphEvidenceState.INFERRED)
        explanation = explain_edge(result.graph, edge.edge_id)
        self.assertEqual(explanation.evidence_state, "inferred")
        self.assertIn("not an independent exploitability", explanation.interpretation)
        self.assertEqual(explanation.evidence_ids, ("rel-1",))

    def test_unknown_evidence_is_ignored_not_reinterpreted(self):
        result = build_unified_attack_graph((
            record("other-1", "unrelated.observation", {"reference": "x"}),
        ))
        self.assertEqual(result.ignored_records, ("other-1",))
        self.assertEqual(result.graph.nodes, ())


if __name__ == "__main__":
    unittest.main()
