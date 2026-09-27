"""Evidence-only review order for bounded identity-graph paths.

This does not measure exploitability, likelihood, impact, or risk. It only helps
an analyst inspect directly observed relationships before inferred ones.
"""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon.graph_models import GraphEvidenceState, IdentityGraph
from nightrecon.graph_path import GraphPath, GraphPathLimits, GraphPathQueryResult
from nightrecon.graph_validation import assert_valid_identity_graph


REVIEW_INTERPRETATION = (
    "Evidence review order only; paths do not establish exploitability, "
    "network reachability, or risk."
)


@dataclass(frozen=True)
class GraphPathReview:
    """A graph path with transparent evidence counts, not a risk score."""

    path: GraphPath
    observed_hops: int
    inferred_hops: int
    review_order: int

    def to_dict(self) -> dict:
        return {
            "review_order": self.review_order,
            "observed_hops": self.observed_hops,
            "inferred_hops": self.inferred_hops,
            "inference_present": self.inferred_hops > 0,
            "node_ids": [node.node_id for node in self.path.nodes],
            "edge_ids": [edge.edge_id for edge in self.path.edges],
        }


@dataclass(frozen=True)
class GraphPathReviewResult:
    """Bounded review order retaining the source query's truncation state."""

    start_node_id: str
    target_node_id: str
    reviews: tuple[GraphPathReview, ...]
    truncated: bool
    interpretation: str = REVIEW_INTERPRETATION

    def to_dict(self) -> dict:
        return {
            "start_node_id": self.start_node_id,
            "target_node_id": self.target_node_id,
            "reviews": [item.to_dict() for item in self.reviews],
            "truncated": self.truncated,
            "interpretation": self.interpretation,
        }


def order_graph_paths_for_review(
    graph: IdentityGraph,
    query: GraphPathQueryResult,
    *,
    limits: GraphPathLimits | None = None,
) -> GraphPathReviewResult:
    """Order valid paths by inferred hops, then hop count, then stable IDs."""

    active_limits = limits or GraphPathLimits()
    assert_valid_identity_graph(graph)
    nodes = {node.node_id: node for node in graph.nodes}
    edges = {edge.edge_id: edge for edge in graph.edges}

    if query.start_node_id not in nodes or query.target_node_id not in nodes:
        raise ValueError("path review requires existing start and target nodes")
    if len(query.paths) > active_limits.max_paths:
        raise ValueError("path review exceeds max_paths")

    seen: set[tuple[str, ...]] = set()
    candidates: list[tuple[int, int, tuple[str, ...], GraphPath]] = []

    for path in query.paths:
        if not path.edges or len(path.edges) > active_limits.max_depth:
            raise ValueError("path review requires a bounded non-empty path")
        if len(path.nodes) != len(path.edges) + 1:
            raise ValueError("path review node and edge counts disagree")
        if path.nodes[0].node_id != query.start_node_id:
            raise ValueError("path review start node does not match query")
        if path.nodes[-1].node_id != query.target_node_id:
            raise ValueError("path review target node does not match query")

        node_ids = tuple(node.node_id for node in path.nodes)
        if len(set(node_ids)) != len(node_ids):
            raise ValueError("path review contains a repeated node")
        if any(nodes.get(node.node_id) != node for node in path.nodes):
            raise ValueError("path review contains a node outside the graph")

        edge_ids = tuple(edge.edge_id for edge in path.edges)
        if edge_ids in seen:
            raise ValueError("path review contains a duplicate path")
        seen.add(edge_ids)
        for position, edge in enumerate(path.edges):
            if edges.get(edge.edge_id) != edge:
                raise ValueError("path review contains an edge outside the graph")
            if not isinstance(edge.evidence_state, GraphEvidenceState):
                raise ValueError("path review requires explicit evidence states")
            if (
                edge.source_node_id != node_ids[position]
                or edge.target_node_id != node_ids[position + 1]
            ):
                raise ValueError("path review edge does not connect adjacent nodes")

        inferred = sum(
            edge.evidence_state is GraphEvidenceState.INFERRED
            for edge in path.edges
        )
        candidates.append((inferred, path.hop_count, edge_ids, path))

    candidates.sort(key=lambda item: item[:3])
    reviews = tuple(
        GraphPathReview(
            path=path,
            observed_hops=hops - inferred,
            inferred_hops=inferred,
            review_order=position,
        )
        for position, (inferred, hops, _, path) in enumerate(candidates, start=1)
    )
    return GraphPathReviewResult(
        start_node_id=query.start_node_id,
        target_node_id=query.target_node_id,
        reviews=reviews,
        truncated=query.truncated,
    )
