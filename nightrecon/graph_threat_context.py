"""Attach existing NightRecon KEV/EPSS threat context to vulnerability graph nodes."""

from __future__ import annotations

from nightrecon.graph_builder import GraphBuildLimits, IdentityGraphBuilder
from nightrecon.graph_models import (
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
    IdentityGraph,
)
from nightrecon.threat_context import ThreatContextResult


def add_threat_context_to_identity_graph(
    graph: IdentityGraph,
    threat_context: tuple[ThreatContextResult, ...],
    *,
    observed_at: str = "",
    limits: GraphBuildLimits | None = None,
) -> IdentityGraph:
    """Return a graph with descriptive KEV/EPSS evidence on matching CVEs."""

    context_by_id = {
        item.vulnerability_id.strip().upper(): item
        for item in threat_context
        if item.vulnerability_id.strip()
    }

    builder = IdentityGraphBuilder(limits)

    for node in graph.nodes:
        if node.kind is not GraphNodeKind.VULNERABILITY:
            builder.add_node(node)
            continue

        context = context_by_id.get(node.label.strip().upper())
        if context is None:
            builder.add_node(node)
            continue

        properties = dict(node.properties)
        properties["known_exploited"] = (
            "true" if context.known_exploited else "false"
        )

        optional = (
            ("kev_date_added", context.kev_date_added),
            ("kev_due_date", context.kev_due_date),
            (
                "kev_known_ransomware_campaign_use",
                context.kev_known_ransomware_campaign_use,
            ),
            ("kev_required_action", context.kev_required_action),
            (
                "epss_probability",
                (
                    str(context.epss_probability)
                    if context.epss_probability is not None
                    else ""
                ),
            ),
            (
                "epss_percentile",
                (
                    str(context.epss_percentile)
                    if context.epss_percentile is not None
                    else ""
                ),
            ),
            ("epss_date", context.epss_date),
        )
        for key, value in optional:
            if value != "":
                properties[key] = value

        provenance = tuple(
            sorted(
                set(
                    node.provenance
                    + (
                        GraphProvenance(
                            source_type="threat-context",
                            source_id=context.vulnerability_id.strip().upper(),
                            observed_at=observed_at.strip(),
                        ),
                    )
                ),
                key=lambda item: (
                    item.source_type,
                    item.source_id,
                    item.observed_at,
                ),
            )
        )

        builder.add_node(
            GraphNode.create(
                kind=node.kind,
                natural_key=node.natural_key,
                label=node.label,
                provenance=provenance,
                properties=tuple(properties.items()),
            )
        )

    for edge in graph.edges:
        builder.add_edge(edge)

    return builder.build()
