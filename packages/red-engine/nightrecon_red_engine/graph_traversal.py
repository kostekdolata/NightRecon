"""Bounded deterministic traversal for NightRecon identity graphs."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon_red_engine.graph_index import IdentityGraphIndex
from nightrecon_red_engine.graph_models import GraphNode, IdentityGraph


@dataclass(frozen=True)
class GraphTraversalLimits:
    """Hard ceilings for read-only graph traversal."""

    max_depth: int = 4
    max_nodes: int = 256

    def __post_init__(self) -> None:
        if self.max_depth < 0:
            raise ValueError("max_depth must be at least 0.")
        if self.max_nodes < 1:
            raise ValueError("max_nodes must be at least 1.")


@dataclass(frozen=True)
class GraphTraversalResult:
    """Deterministic breadth-first traversal result."""

    start_node_id: str
    visited: tuple[GraphNode, ...]
    depth_reached: int
    truncated: bool


def traverse_identity_graph(
    graph: IdentityGraph,
    *,
    start_node_id: str,
    relationship: str = "",
    direction: str = "both",
    limits: GraphTraversalLimits | None = None,
) -> GraphTraversalResult:
    """Traverse direct graph relationships using bounded breadth-first search."""

    active_limits = limits or GraphTraversalLimits()
    index = IdentityGraphIndex(graph)
    start = index.node(start_node_id)

    if start is None:
        raise ValueError(f"start node is missing from graph: {start_node_id}")

    visited_ids = {start.node_id}
    ordered = [start]
    frontier = (start,)
    depth = 0
    truncated = False

    while frontier and depth < active_limits.max_depth:
        next_nodes: list[GraphNode] = []

        for current in frontier:
            for neighbor in index.neighbors(
                current.node_id,
                relationship=relationship,
                direction=direction,
            ):
                if neighbor.node_id in visited_ids:
                    continue

                if len(ordered) >= active_limits.max_nodes:
                    truncated = True
                    return GraphTraversalResult(
                        start_node_id=start.node_id,
                        visited=tuple(ordered),
                        depth_reached=depth,
                        truncated=truncated,
                    )

                visited_ids.add(neighbor.node_id)
                ordered.append(neighbor)
                next_nodes.append(neighbor)

        if not next_nodes:
            break

        frontier = tuple(next_nodes)
        depth += 1

    if frontier and depth >= active_limits.max_depth:
        truncated = any(
            neighbor.node_id not in visited_ids
            for current in frontier
            for neighbor in index.neighbors(
                current.node_id,
                relationship=relationship,
                direction=direction,
            )
        )

    return GraphTraversalResult(
        start_node_id=start.node_id,
        visited=tuple(ordered),
        depth_reached=depth,
        truncated=truncated,
    )
