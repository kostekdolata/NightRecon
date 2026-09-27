"""Deterministic bounded assembly for NightRecon identity graphs."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon.graph_models import GraphEdge, GraphNode, IdentityGraph


@dataclass(frozen=True)
class GraphBuildLimits:
    """Hard in-memory graph ceilings for one build."""

    max_nodes: int = 10_000
    max_edges: int = 25_000

    def __post_init__(self) -> None:
        if self.max_nodes < 1:
            raise ValueError("max_nodes must be at least 1")
        if self.max_edges < 0:
            raise ValueError("max_edges must not be negative")


class IdentityGraphBuilder:
    """Bounded deterministic graph builder with duplicate rejection."""

    def __init__(self, limits: GraphBuildLimits | None = None) -> None:
        self._limits = limits or GraphBuildLimits()
        self._nodes: dict[str, GraphNode] = {}
        self._edges: dict[str, GraphEdge] = {}

    def add_node(self, node: GraphNode) -> None:
        existing = self._nodes.get(node.node_id)
        if existing is not None:
            if existing != node:
                raise ValueError(f"conflicting graph node: {node.node_id}")
            return
        if len(self._nodes) >= self._limits.max_nodes:
            raise ValueError("graph node limit exceeded")
        self._nodes[node.node_id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        if edge.source_node_id not in self._nodes:
            raise ValueError("graph edge source node is missing")
        if edge.target_node_id not in self._nodes:
            raise ValueError("graph edge target node is missing")

        existing = self._edges.get(edge.edge_id)
        if existing is not None:
            if existing != edge:
                raise ValueError(f"conflicting graph edge: {edge.edge_id}")
            return
        if len(self._edges) >= self._limits.max_edges:
            raise ValueError("graph edge limit exceeded")
        self._edges[edge.edge_id] = edge

    def build(self) -> IdentityGraph:
        return IdentityGraph(
            nodes=tuple(self._nodes[key] for key in sorted(self._nodes)),
            edges=tuple(self._edges[key] for key in sorted(self._edges)),
        )
