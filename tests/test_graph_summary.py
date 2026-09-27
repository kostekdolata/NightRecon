"""Tests for descriptive NightRecon identity graph summaries."""

import unittest

from nightrecon.graph_builder import IdentityGraphBuilder
from nightrecon.graph_models import (
    GraphEdge,
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
)
from nightrecon.graph_summary import summarize_identity_graph


class GraphSummaryTests(unittest.TestCase):
    def test_summary_counts_nodes_edges_and_relationships(self):
        provenance = (
            GraphProvenance(source_type="test", source_id="summary"),
        )
        asset = GraphNode.create(
            kind=GraphNodeKind.ASSET,
            natural_key="192.0.2.90",
            label="asset",
            provenance=provenance,
        )
        service = GraphNode.create(
            kind=GraphNodeKind.SERVICE,
            natural_key="192.0.2.90:443/tcp",
            label="https",
            provenance=provenance,
        )
        vulnerability = GraphNode.create(
            kind=GraphNodeKind.VULNERABILITY,
            natural_key="nvd:CVE-2026-9001",
            label="CVE-2026-9001",
            provenance=provenance,
        )
        builder = IdentityGraphBuilder()
        for node in (asset, service, vulnerability):
            builder.add_node(node)
        builder.add_edge(
            GraphEdge.create(
                source_node_id=asset.node_id,
                target_node_id=service.node_id,
                relationship="exposes",
                evidence_state=GraphEvidenceState.OBSERVED,
                provenance=provenance,
            )
        )
        builder.add_edge(
            GraphEdge.create(
                source_node_id=service.node_id,
                target_node_id=vulnerability.node_id,
                relationship="matched-vulnerability",
                evidence_state=GraphEvidenceState.OBSERVED,
                provenance=provenance,
            )
        )

        summary = summarize_identity_graph(builder.build())

        self.assertEqual(summary.node_count, 3)
        self.assertEqual(summary.edge_count, 2)
        self.assertEqual(summary.asset_count, 1)
        self.assertEqual(summary.service_count, 1)
        self.assertEqual(summary.vulnerability_count, 1)
        self.assertEqual(summary.observed_edge_count, 2)
        self.assertEqual(summary.inferred_edge_count, 0)
        self.assertEqual(
            summary.relationship_counts,
            (("exposes", 1), ("matched-vulnerability", 1)),
        )

    def test_empty_graph_summary_is_zeroed(self):
        summary = summarize_identity_graph(
            IdentityGraphBuilder().build()
        )

        self.assertEqual(summary.node_count, 0)
        self.assertEqual(summary.edge_count, 0)
        self.assertEqual(summary.relationship_counts, ())


if __name__ == "__main__":
    unittest.main()
