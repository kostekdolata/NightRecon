"""Bounded evidence-backed path discovery for NightRecon identity graphs."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from nightrecon_red_engine.graph_index import IdentityGraphIndex
from nightrecon_red_engine.graph_models import GraphEdge, GraphNode, IdentityGraph


@dataclass(frozen=True)
class GraphPathLimits:
    """Hard ceilings for deterministic path discovery."""

    max_depth: int = 6
    max_paths: int = 128
    max_expansions: int = 10_000

    def __post_init__(self) -> None:
        if self.max_depth < 1:
            raise ValueError("max_depth must be at least 1")
        if self.max_paths < 1:
            raise ValueError("max_paths must be at least 1")
        if self.max_expansions < 1:
            raise ValueError("max_expansions must be at least 1")


@dataclass(frozen=True)
class GraphPath:
    """One evidence-backed directed path through the graph."""

    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]

    @property
    def hop_count(self) -> int:
        return len(self.edges)


@dataclass(frozen=True)
class GraphPathQueryResult:
    """Deterministic bounded path-query result."""

    start_node_id: str
    target_node_id: str
    paths: tuple[GraphPath, ...]
    truncated: bool


def find_identity_graph_paths(
    graph: IdentityGraph,
    *,
    start_node_id: str,
    target_node_id: str,
    relationships: tuple[str, ...] = (),
    limits: GraphPathLimits | None = None,
) -> GraphPathQueryResult:
    """Find bounded simple directed paths without ranking or exploit claims."""

    active_limits = limits or GraphPathLimits()
    index = IdentityGraphIndex(graph)
    start = index.node(start_node_id)
    target = index.node(target_node_id)

    if start is None:
        raise ValueError(f"start node is missing from graph: {start_node_id}")
    if target is None:
        raise ValueError(f"target node is missing from graph: {target_node_id}")
    if start.node_id == target.node_id:
        return GraphPathQueryResult(
            start_node_id=start.node_id,
            target_node_id=target.node_id,
            paths=(GraphPath(nodes=(start,), edges=()),),
            truncated=False,
        )

    allowed = {item.strip().lower() for item in relationships if item.strip()}
    paths: list[GraphPath] = []
    queue: deque[tuple[tuple[GraphNode, ...], tuple[GraphEdge, ...]]] = deque([
        ((start,), ())
    ])
    truncated = False
    expanded = 0

    while queue:
        if expanded >= active_limits.max_expansions:
            truncated = True
            break

        nodes, edges = queue.popleft()
        expanded += 1
        current = nodes[-1]

        for edge in index.outgoing_edges(current.node_id):
            if allowed and edge.relationship not in allowed:
                continue
            next_node = index.node(edge.target_node_id)
            if next_node is None:
                continue
            if any(node.node_id == next_node.node_id for node in nodes):
                continue
            if len(edges) >= active_limits.max_depth:
                truncated = True
                continue

            next_nodes = nodes + (next_node,)
            next_edges = edges + (edge,)

            if next_node.node_id == target.node_id:
                if len(paths) >= active_limits.max_paths:
                    truncated = True
                    return GraphPathQueryResult(
                        start_node_id=start.node_id,
                        target_node_id=target.node_id,
                        paths=tuple(paths),
                        truncated=truncated,
                    )
                paths.append(GraphPath(nodes=next_nodes, edges=next_edges))
                continue

            if expanded + len(queue) >= active_limits.max_expansions:
                truncated = True
                continue
            queue.append((next_nodes, next_edges))

    return GraphPathQueryResult(
        start_node_id=start.node_id,
        target_node_id=target.node_id,
        paths=tuple(paths),
        truncated=truncated,
    )
