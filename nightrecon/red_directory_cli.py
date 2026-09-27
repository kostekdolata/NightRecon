"""Explicit offline directory import for Red Night; no directory connections."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from collections.abc import Sequence

from nightrecon.graph_builder import IdentityGraphBuilder
from nightrecon.graph_identity_projection import add_identity_evidence_to_identity_graph
from nightrecon.graph_path import GraphPathLimits, find_identity_graph_paths
from nightrecon.graph_path_review import order_graph_paths_for_review
from nightrecon.graph_report import IdentityGraphReport
from nightrecon.graph_snapshot import create_identity_graph_snapshot_manifest
from nightrecon.red_directory_import import (
    DirectoryImportLimits,
    directory_natural_key,
    import_directory_snapshot,
)


def main(argv: Sequence[str]) -> None:
    """Summarize a bounded local export; emit graph details only on opt-in."""

    parser = argparse.ArgumentParser(prog="red-night identity")
    operations = parser.add_subparsers(dest="operation", required=True)
    importer = operations.add_parser("import", help="Review a local normalized directory snapshot.")
    importer.add_argument("path", help="Local UTF-8 JSON snapshot (no live LDAP connection).")
    importer.add_argument("--source-id", required=True, help="Non-secret evidence source ID.")
    importer.add_argument("--start-dn", help="Imported user or group DN to review from.")
    importer.add_argument("--target-dn", help="Imported group DN to review paths to.")
    importer.add_argument(
        "--include-graph", action="store_true",
        help="Include graph labels and provenance in JSON output (may identify people).",
    )
    args = parser.parse_args(argv)
    if (args.start_dn is None) != (args.target_dn is None):
        parser.error("--start-dn and --target-dn must be supplied together")

    limits = DirectoryImportLimits()
    try:
        with Path(args.path).open("rb") as source:
            payload = source.read(limits.max_bytes + 1)
        imported = import_directory_snapshot(
            payload, source_id=args.source_id, limits=limits,
        )
        graph = add_identity_evidence_to_identity_graph(
            IdentityGraphBuilder().build(), imported.evidence,
        )
    except (OSError, ValueError) as exc:
        print(f"red-night identity: {exc}", file=sys.stderr)
        raise SystemExit(2) from None

    manifest = create_identity_graph_snapshot_manifest(graph)
    output = {
        "schema_version": manifest.schema_version,
        "identities": len(imported.evidence.identities),
        "groups": len(imported.evidence.groups),
        "observed_memberships": len(imported.evidence.memberships),
        "unresolved_members": imported.unresolved_members,
        "graph_sha256": manifest.graph_sha256,
        "interpretation": "Offline evidence only; no privilege or exploitability verdict.",
    }
    if args.start_dn is not None:
        try:
            nodes_by_key = {node.natural_key: node for node in graph.nodes}
            start = (
                nodes_by_key.get(directory_natural_key("user", args.start_dn))
                or nodes_by_key.get(directory_natural_key("group", args.start_dn))
            )
            target = nodes_by_key.get(directory_natural_key("group", args.target_dn))
            if start is None or target is None or start.node_id == target.node_id:
                raise ValueError("path endpoints must be distinct imported nodes; target must be a group")
            path_limits = GraphPathLimits(
                max_depth=6, max_paths=128, max_expansions=2_048,
            )
            paths = find_identity_graph_paths(
                graph, start_node_id=start.node_id, target_node_id=target.node_id,
                relationships=("member-of",), limits=path_limits,
            )
            review = order_graph_paths_for_review(graph, paths, limits=path_limits)
        except ValueError as exc:
            print(f"red-night identity: {exc}", file=sys.stderr)
            raise SystemExit(2) from None
        output["path_review"] = {
            "paths": len(review.reviews),
            "truncated": review.truncated,
            "limits": {
                "max_depth": path_limits.max_depth,
                "max_paths": path_limits.max_paths,
                "max_expansions": path_limits.max_expansions,
            },
            "interpretation": review.interpretation,
        }
    if args.include_graph:
        output["graph"] = IdentityGraphReport.create(graph).to_dict()
        if args.start_dn is not None:
            output["path_review"]["reviews"] = [
                item.to_dict() for item in review.reviews
            ]
    print(json.dumps(output, sort_keys=True))
