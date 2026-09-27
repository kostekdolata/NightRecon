"""Explicit offline directory import for Red Night; no directory connections."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from hashlib import sha256

from nightrecon.graph_builder import IdentityGraphBuilder
from nightrecon.graph_identity_projection import add_identity_evidence_to_identity_graph
from nightrecon.graph_report import IdentityGraphReport
from nightrecon.graph_snapshot import create_identity_graph_snapshot_manifest
from nightrecon.red_directory_import import DirectoryImportLimits, import_directory_snapshot
from nightrecon_shared_core.contracts import (
    EngagementEnvelope,
    EngagementMetadata,
    EvidenceRecord,
)
from nightrecon_shared_core.file_store import FileEngagementStore


def _evidence_record(
    *,
    engagement_id: str,
    source_id: str,
    graph_sha256: str,
    graph_schema_version: int,
    identity_count: int,
    group_count: int,
    observed_membership_count: int,
    unresolved_member_count: int,
) -> EvidenceRecord:
    observed_at = datetime.now(timezone.utc).isoformat()
    evidence_id = "red-identity-" + sha256(
        f"{engagement_id}:{source_id}:{graph_sha256}:{observed_at}".encode("utf-8")
    ).hexdigest()
    return EvidenceRecord(
        engagement_id=engagement_id,
        evidence_id=evidence_id,
        source_night="red",
        evidence_type="identity.directory-snapshot",
        observed_at=observed_at,
        provenance=source_id,
        data={
            "identity_count": identity_count,
            "group_count": group_count,
            "observed_membership_count": observed_membership_count,
            "unresolved_member_count": unresolved_member_count,
            "graph_sha256": graph_sha256,
            "graph_schema_version": graph_schema_version,
        },
        limitations=(
            "Offline evidence only",
            "No privilege or exploitability verdict",
            "No live directory collection performed",
        ),
    )


def _store_error(exc: Exception) -> None:
    print(f"red-night identity: {exc}", file=sys.stderr)
    raise SystemExit(2) from None


def main(argv: Sequence[str]) -> None:
    parser = argparse.ArgumentParser(prog="red-night identity")
    operations = parser.add_subparsers(dest="operation", required=True)

    importer = operations.add_parser("import", help="Review a local normalized directory snapshot.")
    importer.add_argument("path", help="Local UTF-8 JSON snapshot (no live LDAP connection).")
    importer.add_argument("--source-id", required=True, help="Non-secret evidence source ID.")
    importer.add_argument("--engagement-id", help="Approved engagement ID for envelope/store output.")
    importer.add_argument("--export-envelope", action="store_true")
    importer.add_argument("--store", help="Optional portable engagement-store JSON path.")
    importer.add_argument("--include-graph", action="store_true")

    listing = operations.add_parser("store-list", help="Read portable shared evidence.")
    listing.add_argument("store")
    listing.add_argument("--engagement-id", required=True)
    listing.add_argument("--source-night")
    listing.add_argument("--evidence-type")

    metadata_cmd = operations.add_parser(
        "store-metadata", help="Create engagement coordination metadata."
    )
    metadata_cmd.add_argument("store")
    metadata_cmd.add_argument("--engagement-id", required=True)
    metadata_cmd.add_argument("--name", required=True)
    metadata_cmd.add_argument("--authorization-reference", required=True)
    metadata_cmd.add_argument("--status", default="planned")
    metadata_cmd.add_argument("--description")

    export_cmd = operations.add_parser("store-export", help="Export one engagement envelope.")
    export_cmd.add_argument("store")
    export_cmd.add_argument("--engagement-id", required=True)
    export_cmd.add_argument("--output", required=True)

    import_cmd = operations.add_parser("store-import", help="Import one engagement envelope.")
    import_cmd.add_argument("store")
    import_cmd.add_argument("input")

    args = parser.parse_args(argv)

    try:
        if args.operation == "store-list":
            store = FileEngagementStore(args.store)
            records = store.records(
                args.engagement_id,
                source_night=args.source_night,
                evidence_type=args.evidence_type,
            )
            print(EngagementEnvelope(
                engagement_id=args.engagement_id,
                metadata=store.metadata(args.engagement_id),
                records=records,
            ).to_json())
            return

        if args.operation == "store-metadata":
            store = FileEngagementStore(args.store)
            metadata = EngagementMetadata(
                engagement_id=args.engagement_id,
                name=args.name,
                created_at=datetime.now(timezone.utc).isoformat(),
                authorization_reference=args.authorization_reference,
                status=args.status,
                description=args.description,
            )
            store.set_metadata(metadata)
            print(json.dumps(metadata.to_dict(), sort_keys=True))
            return

        if args.operation == "store-export":
            store = FileEngagementStore(args.store)
            envelope = store.export_envelope(args.engagement_id)
            Path(args.output).write_text(envelope.to_json() + "\n", encoding="utf-8")
            print(json.dumps({
                "engagement_id": args.engagement_id,
                "records": len(envelope.records),
                "output": str(Path(args.output)),
            }, sort_keys=True))
            return

        if args.operation == "store-import":
            envelope = EngagementEnvelope.from_json(
                Path(args.input).read_text(encoding="utf-8")
            )
            FileEngagementStore(args.store).import_envelope(envelope)
            print(json.dumps({
                "engagement_id": envelope.engagement_id,
                "records": len(envelope.records),
                "source_nights": sorted({
                    record.source_night for record in envelope.records
                }),
            }, sort_keys=True))
            return
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        _store_error(exc)

    if (args.export_envelope or args.store) and not args.engagement_id:
        _store_error(ValueError(
            "--engagement-id is required with --export-envelope or --store"
        ))

    limits = DirectoryImportLimits()
    try:
        with Path(args.path).open("rb") as source:
            payload = source.read(limits.max_bytes + 1)
        imported = import_directory_snapshot(
            payload, source_id=args.source_id, limits=limits
        )
        graph = add_identity_evidence_to_identity_graph(
            IdentityGraphBuilder().build(), imported.evidence,
        )
    except (OSError, ValueError) as exc:
        _store_error(exc)

    manifest = create_identity_graph_snapshot_manifest(graph)
    envelope: EngagementEnvelope | None = None
    if args.export_envelope or args.store:
        envelope = EngagementEnvelope(
            engagement_id=args.engagement_id,
            records=(_evidence_record(
                engagement_id=args.engagement_id,
                source_id=args.source_id,
                graph_sha256=manifest.graph_sha256,
                graph_schema_version=manifest.schema_version,
                identity_count=len(imported.evidence.identities),
                group_count=len(imported.evidence.groups),
                observed_membership_count=len(imported.evidence.memberships),
                unresolved_member_count=imported.unresolved_members,
            ),),
        )
        if args.store:
            try:
                FileEngagementStore(args.store).append_envelope(envelope)
            except (OSError, ValueError) as exc:
                _store_error(exc)

    if args.export_envelope:
        assert envelope is not None
        print(envelope.to_json())
        return

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
