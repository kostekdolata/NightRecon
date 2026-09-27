"""Deterministic read-only indexes for NightRecon identity graphs."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon.graph_models import GraphEdge, GraphNode, GraphNodeKind, IdentityGraph


@dataclass(frozen=True)
class IdentityGraphIndex:
    """Read-only deterministic indexes over one immutable identity graph."""

    graph: IdentityGraph

    def node(self, node_id: str) -> GraphNode | None:
        """Return one node by stable identifier."""

        return next(
            (
                node
                for node in self.graph.nodes
                if node.node_id == node_id
            ),
            None,
        )

    def nodes_by_kind(
        self,
        kind: GraphNodeKind,
    ) -> tuple[GraphNode, ...]:
        """Return nodes of one kind in deterministic graph order."""

        return tuple(
            node
            for node in self.graph.nodes
            if node.kind is kind
        )

    def outgoing_edges(
        self,
        node_id: str,
        *,
        relationship: str = "",
    ) -> tuple[GraphEdge, ...]:
        """Return deterministic outgoing edges for one node."""

        relation = relationship.strip().lower()
        return tuple(
            edge
            for edge in self.graph.edges
            if edge.source_node_id == node_id
            and (
                not relation
                or edge.relationship == relation
            )
        )

    def incoming_edges(
        self,
        node_id: str,
        *,
        relationship: str = "",
    ) -> tuple[GraphEdge, ...]:
        """Return deterministic incoming edges for one node."""

        relation = relationship.strip().lower()
        return tuple(
            edge
            for edge in self.graph.edges
            if edge.target_node_id == node_id
            and (
                not relation
                or edge.relationship == relation
            )
        )

    def neighbors(
        self,
        node_id: str,
        *,
        relationship: str = "",
        direction: str = "both",
    ) -> tuple[GraphNode, ...]:
        """Return unique direct neighbors without performing path search."""

        if direction not in {"outgoing", "incoming", "both"}:
            raise ValueError(
                "direction must be outgoing, incoming, or both."
            )

        node_ids: set[str] = set()

        if direction in {"outgoing", "both"}:
            node_ids.update(
                edge.target_node_id
                for edge in self.outgoing_edges(
                    node_id,
                    relationship=relationship,
                )
            )

        if direction in {"incoming", "both"}:
            node_ids.update(
                edge.source_node_id
                for edge in self.incoming_edges(
                    node_id,
                    relationship=relationship,
                )
            )

        return tuple(
            node
            for node in self.graph.nodes
            if node.node_id in node_ids
        )
