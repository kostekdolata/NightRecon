"""Deterministic fingerprints for immutable NightRecon identity graph snapshots."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from nightrecon.graph_models import IdentityGraph
from nightrecon.graph_report import GRAPH_REPORT_SCHEMA_VERSION, IdentityGraphReport


@dataclass(frozen=True)
class IdentityGraphSnapshotManifest:
    """Reproducible identity graph snapshot metadata."""

    schema_version: int
    graph_sha256: str
    node_count: int
    edge_count: int


def create_identity_graph_snapshot_manifest(
    graph: IdentityGraph,
) -> IdentityGraphSnapshotManifest:
    """Create a deterministic SHA-256 manifest for one graph snapshot."""

    report = IdentityGraphReport.create(graph).to_dict()
    payload = json.dumps(
        report,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()

    return IdentityGraphSnapshotManifest(
        schema_version=GRAPH_REPORT_SCHEMA_VERSION,
        graph_sha256=digest,
        node_count=len(graph.nodes),
        edge_count=len(graph.edges),
    )
