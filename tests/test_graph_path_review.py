"""Tests for conservative evidence-only ordering of graph paths."""

import unittest

from nightrecon.graph_builder import IdentityGraphBuilder
from nightrecon.graph_models import (
    GraphEdge,
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
)
from nightrecon.graph_path import (
    GraphPath,
    GraphPathLimits,
    GraphPathQueryResult,
    find_identity_graph_paths,
)
from nightrecon.graph_path_review import order_graph_paths_for_review


class GraphPathReviewTests(unittest.TestCase):
    def build_paths(self):
        provenance = (GraphProvenance(source_type="test", source_id="review"),)
        identity = GraphNode.create(
            kind=GraphNodeKind.IDENTITY, natural_key="alice", label="Alice",
            provenance=provenance,
        )
        group_a = GraphNode.create(
            kind=GraphNodeKind.GROUP, natural_key="a", label="A",
            provenance=provenance,
        )
        group_b = GraphNode.create(
            kind=GraphNodeKind.GROUP, natural_key="b", label="B",
            provenance=provenance,
        )
        permission = GraphNode.create(
            kind=GraphNodeKind.PERMISSION, natural_key="p", label="Permission",
            provenance=provenance,
        )
        asset = GraphNode.create(
            kind=GraphNodeKind.ASSET, natural_key="192.0.2.10",
            label="Asset", provenance=provenance,
        )
        builder = IdentityGraphBuilder()
        for node in (identity, group_a, group_b, permission, asset):
            builder.add_node(node)
        relations = (
            (identity, group_a, "member-of", GraphEvidenceState.OBSERVED),
            (group_a, group_b, "member-of", GraphEvidenceState.OBSERVED),
            (group_b, permission, "has-permission", GraphEvidenceState.OBSERVED),
            (identity, permission, "has-permission", GraphEvidenceState.INFERRED),
            (permission, asset, "applies-to", GraphEvidenceState.OBSERVED),
        )
        for source, target, relationship, state in relations:
            builder.add_edge(GraphEdge.create(
                source_node_id=source.node_id,
                target_node_id=target.node_id,
                relationship=relationship,
                evidence_state=state,
                provenance=provenance,
            ))
        graph = builder.build()
        query = find_identity_graph_paths(
            graph, start_node_id=identity.node_id, target_node_id=asset.node_id,
        )
        return graph, query

    def test_observed_chain_precedes_shorter_inferred_chain(self):
        graph, query = self.build_paths()
        self.assertEqual(tuple(path.hop_count for path in query.paths), (2, 4))
        review = order_graph_paths_for_review(graph, query)
        self.assertEqual(
            tuple(item.path.hop_count for item in review.reviews), (4, 2)
        )
        self.assertEqual(
            tuple(item.inferred_hops for item in review.reviews), (0, 1)
        )
        self.assertEqual(
            tuple(item.review_order for item in review.reviews), (1, 2)
        )
        self.assertEqual(len(review.reviews[0].path.edges), 4)

    def test_order_is_independent_of_input_path_order(self):
        graph, query = self.build_paths()
        reversed_query = GraphPathQueryResult(
            query.start_node_id, query.target_node_id, tuple(reversed(query.paths)), True
        )
        review = order_graph_paths_for_review(graph, reversed_query)
        self.assertTrue(review.truncated)
        self.assertEqual(
            review.reviews[0].path.edges, query.paths[1].edges
        )
        record = review.to_dict()
        self.assertNotIn("risk_score", str(record))
        self.assertNotIn("exploitable", record["reviews"][0])
        self.assertIn("do not establish exploitability", record["interpretation"])

    def test_forged_and_disconnected_evidence_fail_closed(self):
        graph, query = self.build_paths()
        valid = query.paths[0]
        forged = GraphPath(
            nodes=valid.nodes,
            edges=(query.paths[1].edges[0], valid.edges[-1]),
        )
        with self.assertRaisesRegex(ValueError, "edge does not connect"):
            order_graph_paths_for_review(graph, GraphPathQueryResult(
                query.start_node_id, query.target_node_id, (forged,), False,
            ))

    def test_duplicate_and_over_budget_paths_fail_closed(self):
        graph, query = self.build_paths()
        with self.assertRaisesRegex(ValueError, "duplicate path"):
            order_graph_paths_for_review(graph, GraphPathQueryResult(
                query.start_node_id, query.target_node_id,
                (query.paths[0], query.paths[0]), False,
            ))
        with self.assertRaisesRegex(ValueError, "max_paths"):
            order_graph_paths_for_review(
                graph, query, limits=GraphPathLimits(max_depth=6, max_paths=1),
            )


if __name__ == "__main__":
    unittest.main()
