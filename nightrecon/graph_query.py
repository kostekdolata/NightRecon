"""Typed deterministic read-only queries for NightRecon identity graphs."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon.graph_index import IdentityGraphIndex
from nightrecon.graph_models import GraphEdge, GraphNode, GraphNodeKind, IdentityGraph


@dataclass(frozen=True)
class GraphQueryResult:
    """Deterministic read-only subset of one identity graph."""

    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]


def query_identity_graph(
    graph: IdentityGraph,
    *,
    node_kinds: tuple[GraphNodeKind, ...] = (),
    relationship: str = "",
    source_node_id: str = "",
    target_node_id: str = "",
) -> GraphQueryResult:
    """Return a deterministic graph subset using explicit structural filters."""

    selected_kinds = set(node_kinds)
    relation = relationship.strip().lower()
    index = IdentityGraphIndex(graph)

    if source_node_id and index.node(source_node_id) is None:
        raise ValueError(f"source node is missing from graph: {source_node_id}")
    if target_node_id and index.node(target_node_id) is None:
        raise ValueError(f"target node is missing from graph: {target_node_id}")

    edges = tuple(
        edge
        for edge in graph.edges
        if (not relation or edge.relationship == relation)
        and (not source_node_id or edge.source_node_id == source_node_id)
        and (not target_node_id or edge.target_node_id == target_node_id)
    )

    referenced_node_ids = {
        node_id
        for edge in edges
        for node_id in (edge.source_node_id, edge.target_node_id)
    }

    nodes = tuple(
        node
        for node in graph.nodes
        if (
            (not selected_kinds or node.kind in selected_kinds)
            and (
                not edges
                or node.node_id in referenced_node_ids
            )
        )
    )

    if selected_kinds and edges:
        allowed_ids = {node.node_id for node in nodes}
        edges = tuple(
            edge
            for edge in edges
            if edge.source_node_id in allowed_ids
            and edge.target_node_id in allowed_ids
        )

    if not relation and not source_node_id and not target_node_id:
        nodes = tuple(
            node
            for node in graph.nodes
            if not selected_kinds or node.kind in selected_kinds
        )
        allowed_ids = {node.node_id for node in nodes}
        edges = tuple(
            edge
            for edge in graph.edges
            if edge.source_node_id in allowed_ids
            and edge.target_node_id in allowed_ids
        )

    return GraphQueryResult(nodes=nodes, edges=edges)
