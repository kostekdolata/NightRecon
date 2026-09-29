"""Deterministic exact cross-surface graph correlation.

This module correlates already-observed graph facts. It does not perform DNS,
network access, fuzzy matching, or exploitability analysis.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from nightrecon_red_engine.graph_builder import GraphBuildLimits, IdentityGraphBuilder
from nightrecon_red_engine.graph_models import (
    GraphEdge,
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
    IdentityGraph,
)


def _normalize_hostname(value: str) -> str:
    normalized = value.strip().casefold().rstrip(".")
    if not normalized or any(character.isspace() for character in normalized):
        return ""
    return normalized


def _property_map(node: GraphNode) -> dict[str, str]:
    return dict(node.properties)


def _csv_hostnames(value: str) -> tuple[str, ...]:
    if not value:
        return ()
    result = {
        normalized
        for item in value.split(",")
        if (normalized := _normalize_hostname(item))
    }
    return tuple(sorted(result))


def _asset_hostnames(node: GraphNode) -> tuple[str, ...]:
    properties = _property_map(node)
    return _csv_hostnames(properties.get("hostnames", ""))


def _identity_hostnames(node: GraphNode) -> tuple[str, ...]:
    properties = _property_map(node)
    values: set[str] = set()
    dns_hostname = _normalize_hostname(properties.get("dns_hostname", ""))
    if dns_hostname:
        values.add(dns_hostname)
    values.update(_csv_hostnames(properties.get("spn_hosts", "")))
    return tuple(sorted(values))


def _opaque_hostname_key(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CrossSurfaceCorrelationLimits:
    max_edges: int = 5_000
    max_unresolved: int = 5_000

    def __post_init__(self) -> None:
        if self.max_edges < 0:
            raise ValueError("max_edges must not be negative")
        if self.max_unresolved < 0:
            raise ValueError("max_unresolved must not be negative")


@dataclass(frozen=True)
class CrossSurfaceUnresolved:
    identity_key: str
    correlation_basis: str
    key_sha256: str
    reason: str
    candidate_count: int

    def __post_init__(self) -> None:
        if not self.identity_key.strip():
            raise ValueError("identity_key must not be empty")
        if self.correlation_basis != "exact-hostname":
            raise ValueError("unsupported correlation basis")
        if len(self.key_sha256) != 64:
            raise ValueError("key_sha256 must be a SHA-256 hex digest")
        if self.reason not in {
            "no-exact-asset-hostname-match",
            "ambiguous-asset-hostname",
        }:
            raise ValueError("unsupported unresolved correlation reason")
        if self.candidate_count < 0:
            raise ValueError("candidate_count must not be negative")


@dataclass(frozen=True)
class CrossSurfaceCorrelationResult:
    graph: IdentityGraph
    correlated_edge_ids: tuple[str, ...]
    unresolved: tuple[CrossSurfaceUnresolved, ...]


def correlate_exact_cross_surface_evidence(
    graph: IdentityGraph,
    *,
    limits: CrossSurfaceCorrelationLimits | None = None,
) -> CrossSurfaceCorrelationResult:
    """Correlate exact hostname evidence across identity and network surfaces."""

    active = limits or CrossSurfaceCorrelationLimits()
    builder = IdentityGraphBuilder(
        GraphBuildLimits(
            max_nodes=max(len(graph.nodes), 1),
            max_edges=len(graph.edges) + active.max_edges,
        )
    )
    for node in graph.nodes:
        builder.add_node(node)
    for edge in graph.edges:
        builder.add_edge(edge)

    assets_by_hostname: dict[str, list[GraphNode]] = {}
    identities: list[GraphNode] = []

    for node in graph.nodes:
        if node.kind is GraphNodeKind.ASSET:
            for hostname in _asset_hostnames(node):
                assets_by_hostname.setdefault(hostname, []).append(node)
        elif node.kind is GraphNodeKind.IDENTITY:
            if _identity_hostnames(node):
                identities.append(node)

    pair_keys: dict[tuple[str, str], set[str]] = {}
    unresolved: list[CrossSurfaceUnresolved] = []

    for identity in sorted(identities, key=lambda item: item.node_id):
        for hostname in _identity_hostnames(identity):
            candidates = tuple(sorted(
                assets_by_hostname.get(hostname, ()),
                key=lambda item: item.node_id,
            ))
            key_hash = _opaque_hostname_key(hostname)
            if len(candidates) != 1:
                if len(unresolved) >= active.max_unresolved:
                    raise ValueError("cross-surface unresolved correlation limit exceeded")
                unresolved.append(CrossSurfaceUnresolved(
                    identity_key=identity.natural_key,
                    correlation_basis="exact-hostname",
                    key_sha256=key_hash,
                    reason=(
                        "no-exact-asset-hostname-match"
                        if not candidates
                        else "ambiguous-asset-hostname"
                    ),
                    candidate_count=len(candidates),
                ))
                continue
            asset = candidates[0]
            pair_keys.setdefault(
                (identity.node_id, asset.node_id),
                set(),
            ).add(key_hash)

    if len(pair_keys) > active.max_edges:
        raise ValueError("cross-surface correlation edge limit exceeded")

    correlated: list[str] = []
    for (identity_id, asset_id), key_hashes in sorted(pair_keys.items()):
        provenance = (
            GraphProvenance(
                source_type="cross-surface-correlation",
                source_id=sha256(
                    (
                        identity_id
                        + "\x1f"
                        + asset_id
                        + "\x1f"
                        + "\x1f".join(sorted(key_hashes))
                    ).encode("utf-8")
                ).hexdigest(),
            ),
        )
        edge = GraphEdge.create(
            source_node_id=identity_id,
            target_node_id=asset_id,
            relationship="correlates-to",
            evidence_state=GraphEvidenceState.INFERRED,
            provenance=provenance,
            properties=(
                ("claim", "exact-evidence-correlation-only"),
                ("correlation_basis", "exact-hostname"),
                ("matched_key_count", str(len(key_hashes))),
            ),
        )
        builder.add_edge(edge)
        correlated.append(edge.edge_id)

    return CrossSurfaceCorrelationResult(
        graph=builder.build(),
        correlated_edge_ids=tuple(sorted(correlated)),
        unresolved=tuple(sorted(
            unresolved,
            key=lambda item: (
                item.identity_key,
                item.key_sha256,
                item.reason,
                item.candidate_count,
            ),
        )),
    )
