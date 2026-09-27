"""Structured deterministic reporting for NightRecon identity graphs."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from nightrecon.graph_models import IdentityGraph


GRAPH_REPORT_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class IdentityGraphReport:
    """Serializable snapshot of one identity graph."""

    schema_version: int
    nodes: tuple[dict, ...]
    edges: tuple[dict, ...]

    @classmethod
    def create(cls, graph: IdentityGraph) -> "IdentityGraphReport":
        return cls(
            schema_version=GRAPH_REPORT_SCHEMA_VERSION,
            nodes=tuple(
                {
                    "node_id": node.node_id,
                    "kind": node.kind.value,
                    "natural_key": node.natural_key,
                    "label": node.label,
                    "provenance": tuple(
                        {
                            "source_type": item.source_type,
                            "source_id": item.source_id,
                            "observed_at": item.observed_at,
                        }
                        for item in node.provenance
                    ),
                    "properties": tuple(
                        {
                            "name": key,
                            "value": value,
                        }
                        for key, value in node.properties
                    ),
                }
                for node in graph.nodes
            ),
            edges=tuple(
                {
                    "edge_id": edge.edge_id,
                    "source_node_id": edge.source_node_id,
                    "target_node_id": edge.target_node_id,
                    "relationship": edge.relationship,
                    "evidence_state": edge.evidence_state.value,
                    "provenance": tuple(
                        {
                            "source_type": item.source_type,
                            "source_id": item.source_id,
                            "observed_at": item.observed_at,
                        }
                        for item in edge.provenance
                    ),
                    "properties": tuple(
                        {
                            "name": key,
                            "value": value,
                        }
                        for key, value in edge.properties
                    ),
                }
                for edge in graph.edges
            ),
        )

    def to_dict(self) -> dict:
        data = asdict(self)
        data["summary"] = {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "observed_edges": sum(
                edge["evidence_state"] == "observed"
                for edge in self.edges
            ),
            "inferred_edges": sum(
                edge["evidence_state"] == "inferred"
                for edge in self.edges
            ),
        }
        return data
