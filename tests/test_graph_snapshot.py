"""Tests for deterministic identity graph snapshot manifests."""

import unittest

from nightrecon.graph_builder import IdentityGraphBuilder
from nightrecon.graph_models import (
    GraphEdge,
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
)
from nightrecon.graph_snapshot import create_identity_graph_snapshot_manifest


class GraphSnapshotTests(unittest.TestCase):
    def build_graph(self, reverse=False):
        provenance = (
            GraphProvenance(
                source_type="test",
                source_id="snapshot",
                observed_at="2026-09-27T18:00:00+00:00",
            ),
        )
        asset = GraphNode.create(
            kind=GraphNodeKind.ASSET,
            natural_key="192.0.2.110",
            label="asset",
            provenance=provenance,
        )
        service = GraphNode.create(
            kind=GraphNodeKind.SERVICE,
            natural_key="192.0.2.110:443/tcp",
            label="https",
            provenance=provenance,
        )
        edge = GraphEdge.create(
            source_node_id=asset.node_id,
            target_node_id=service.node_id,
            relationship="exposes",
            evidence_state=GraphEvidenceState.OBSERVED,
            provenance=provenance,
        )

        builder = IdentityGraphBuilder()
        for node in ((service, asset) if reverse else (asset, service)):
            builder.add_node(node)
        builder.add_edge(edge)
        return builder.build()

    def test_manifest_is_deterministic_across_insertion_order(self):
        first = create_identity_graph_snapshot_manifest(
            self.build_graph(reverse=False)
        )
        second = create_identity_graph_snapshot_manifest(
            self.build_graph(reverse=True)
        )

        self.assertEqual(first, second)
        self.assertEqual(len(first.graph_sha256), 64)
        self.assertEqual(first.node_count, 2)
        self.assertEqual(first.edge_count, 1)

    def test_graph_change_changes_snapshot_digest(self):
        graph = self.build_graph()
        first = create_identity_graph_snapshot_manifest(graph)

        provenance = (
            GraphProvenance(
                source_type="test",
                source_id="snapshot",
                observed_at="2026-09-27T18:00:00+00:00",
            ),
        )
        extra = GraphNode.create(
            kind=GraphNodeKind.VULNERABILITY,
            natural_key="nvd:CVE-2026-11000",
            label="CVE-2026-11000",
            provenance=provenance,
        )
        builder = IdentityGraphBuilder()
        for node in graph.nodes:
            builder.add_node(node)
        for edge in graph.edges:
            builder.add_edge(edge)
        builder.add_node(extra)

        second = create_identity_graph_snapshot_manifest(builder.build())

        self.assertNotEqual(first.graph_sha256, second.graph_sha256)
        self.assertEqual(second.node_count, 3)


if __name__ == "__main__":
    unittest.main()
