"""Unified attack graph must be evidence-backed and fail soft on missing entities."""

from __future__ import annotations

import unittest

from nightrecon_red_engine.graph_models import GraphEvidenceState, GraphNodeKind
from nightrecon_red_engine.unified_attack_graph import (
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
