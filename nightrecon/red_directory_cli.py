"""Explicit offline directory import for Red Night; no directory connections."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from collections.abc import Sequence

from nightrecon.graph_builder import IdentityGraphBuilder
from nightrecon.graph_identity_projection import add_identity_evidence_to_identity_graph
from nightrecon.graph_report import IdentityGraphReport
from nightrecon.graph_snapshot import create_identity_graph_snapshot_manifest
from nightrecon.red_directory_import import (
    DirectoryImportLimits,
    import_directory_snapshot,
)


def main(argv: Sequence[str]) -> None:
    """Summarize a bounded local export; emit graph details only on opt-in."""

    parser = argparse.ArgumentParser(prog="red-night identity")
    operations = parser.add_subparsers(dest="operation", required=True)
    importer = operations.add_parser("import", help="Review a local normalized directory snapshot.")
    importer.add_argument("path", help="Local UTF-8 JSON snapshot (no live LDAP connection).")
    importer.add_argument("--source-id", required=True, help="Non-secret evidence source ID.")
    importer.add_argument(
        "--include-graph", action="store_true",
        help="Include graph labels and provenance in JSON output (may identify people).",
    )
    args = parser.parse_args(argv)

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
    if args.include_graph:
        output["graph"] = IdentityGraphReport.create(graph).to_dict()
    print(json.dumps(output, sort_keys=True))
