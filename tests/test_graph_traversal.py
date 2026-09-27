"""Tests for bounded deterministic identity graph traversal."""

import unittest

from nightrecon.graph_builder import IdentityGraphBuilder
from nightrecon.graph_models import (
    GraphEdge,
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
)
from nightrecon.graph_traversal import (
    GraphTraversalLimits,
    traverse_identity_graph,
)


class GraphTraversalTests(unittest.TestCase):
    def build_graph(self):
        provenance = (
            GraphProvenance(source_type="test", source_id="traversal"),
        )
        nodes = [
            GraphNode.create(
                kind=GraphNodeKind.ASSET,
                natural_key="asset",
                label="asset",
                provenance=provenance,
            ),
            GraphNode.create(
                kind=GraphNodeKind.SERVICE,
                natural_key="asset:443/tcp",
                label="https",
                provenance=provenance,
            ),
            GraphNode.create(
                kind=GraphNodeKind.VULNERABILITY,
                natural_key="nvd:CVE-2026-9000",
                label="CVE-2026-9000",
                provenance=provenance,
            ),
            GraphNode.create(
                kind=GraphNodeKind.ASSESSMENT_FINDING,
                natural_key="asset:443/tcp:web.headers:0",
                label="finding",
                provenance=provenance,
            ),
        ]
        builder = IdentityGraphBuilder()
        for node in reversed(nodes):
            builder.add_node(node)
        builder.add_edge(
            GraphEdge.create(
                source_node_id=nodes[0].node_id,
                target_node_id=nodes[1].node_id,
                relationship="exposes",
                evidence_state=GraphEvidenceState.OBSERVED,
                provenance=provenance,
            )
        )
        builder.add_edge(
            GraphEdge.create(
                source_node_id=nodes[1].node_id,
                target_node_id=nodes[2].node_id,
                relationship="matched-vulnerability",
                evidence_state=GraphEvidenceState.OBSERVED,
                provenance=provenance,
            )
        )
        builder.add_edge(
            GraphEdge.create(
                source_node_id=nodes[1].node_id,
                target_node_id=nodes[3].node_id,
                relationship="has-assessment-finding",
                evidence_state=GraphEvidenceState.OBSERVED,
                provenance=provenance,
            )
        )
        return builder.build(), nodes

    def test_breadth_first_traversal_is_deterministic(self):
        graph, nodes = self.build_graph()

        result = traverse_identity_graph(
            graph,
            start_node_id=nodes[0].node_id,
            direction="outgoing",
        )

        self.assertEqual(result.visited[0], nodes[0])
        self.assertEqual(
            {node.node_id for node in result.visited},
            {node.node_id for node in nodes},
        )
        self.assertFalse(result.truncated)

    def test_relationship_filter_limits_traversal(self):
        graph, nodes = self.build_graph()

        result = traverse_identity_graph(
            graph,
            start_node_id=nodes[0].node_id,
            direction="outgoing",
            relationship="exposes",
        )

        self.assertEqual(result.visited, (nodes[0], nodes[1]))

    def test_depth_limit_truncates_without_overrunning(self):
        graph, nodes = self.build_graph()

        result = traverse_identity_graph(
            graph,
            start_node_id=nodes[0].node_id,
            direction="outgoing",
            limits=GraphTraversalLimits(max_depth=1, max_nodes=10),
        )

        self.assertEqual(result.visited, (nodes[0], nodes[1]))
        self.assertTrue(result.truncated)

    def test_node_limit_truncates_without_overrunning(self):
        graph, nodes = self.build_graph()

        result = traverse_identity_graph(
            graph,
            start_node_id=nodes[0].node_id,
            direction="outgoing",
            limits=GraphTraversalLimits(max_depth=4, max_nodes=2),
        )

        self.assertEqual(len(result.visited), 2)
        self.assertTrue(result.truncated)

    def test_missing_start_node_fails_closed(self):
        graph, _ = self.build_graph()

        with self.assertRaisesRegex(
            ValueError,
            "start node is missing",
        ):
            traverse_identity_graph(
                graph,
                start_node_id="missing",
            )


if __name__ == "__main__":
    unittest.main()
