"""Red Night workspace coordination CLI; no collection or active execution."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from collections.abc import Sequence
from dataclasses import asdict
from datetime import datetime, timezone

from nightrecon_shared_core.contracts import EngagementMetadata
from nightrecon_shared_core.workspace import LocalWorkspace


def _error(exc: Exception) -> None:
    print(f"red-night workspace: {exc}", file=sys.stderr)
    raise SystemExit(2) from None


def main(argv: Sequence[str]) -> None:
    parser = argparse.ArgumentParser(prog="red-night workspace")
    operations = parser.add_subparsers(dest="operation", required=True)

    creating = operations.add_parser("create", help="Create an engagement workspace record.")
    creating.add_argument("root")
    creating.add_argument("--engagement-id", required=True)
    creating.add_argument("--name", required=True)
    creating.add_argument("--authorization-reference", required=True)
    creating.add_argument("--status", default="planned")
    creating.add_argument("--description")

    status = operations.add_parser("status", help="Advance an engagement lifecycle status.")
    status.add_argument("root")
    status.add_argument("--engagement-id", required=True)
    status.add_argument("--set", required=True, dest="new_status")

    timeline = operations.add_parser("timeline", help="Show chronological engagement evidence.")
    timeline.add_argument("root")
    timeline.add_argument("--engagement-id", required=True)

    listing = operations.add_parser("list", help="List engagements in a workspace.")
    listing.add_argument("root")

    showing = operations.add_parser("show", help="Show one engagement summary.")
    showing.add_argument("root")
    showing.add_argument("--engagement-id", required=True)

    importing = operations.add_parser("import", help="Merge a portable engagement envelope.")
    importing.add_argument("root")
    importing.add_argument("input")

    exporting = operations.add_parser("export", help="Export one engagement envelope.")
    exporting.add_argument("root")
    exporting.add_argument("--engagement-id", required=True)
    exporting.add_argument("--output", required=True)

    args = parser.parse_args(argv)

    try:
        workspace = LocalWorkspace(args.root)

        if args.operation == "create":
            summary = workspace.create_engagement(EngagementMetadata(
                engagement_id=args.engagement_id,
                name=args.name,
                created_at=datetime.now(timezone.utc).isoformat(),
                authorization_reference=args.authorization_reference,
                status=args.status,
                description=args.description,
            ))
            print(json.dumps(asdict(summary), sort_keys=True))
            return

        if args.operation == "status":
            print(json.dumps(
                asdict(workspace.update_status(args.engagement_id, args.new_status)),
                sort_keys=True,
            ))
            return

        if args.operation == "timeline":
            print(json.dumps(
                [asdict(item) for item in workspace.timeline(args.engagement_id)],
                sort_keys=True,
            ))
            return

        if args.operation == "list":
            print(json.dumps(
                [asdict(item) for item in workspace.summaries()],
                sort_keys=True,
            ))
            return

        if args.operation == "show":
            summary = workspace.summary(args.engagement_id)
            breakdown = workspace.evidence_breakdown(args.engagement_id)
            print(json.dumps({
                "summary": asdict(summary),
                "breakdown": asdict(breakdown),
            }, sort_keys=True))
            return

        if args.operation == "import":
            report = workspace.import_file(args.input)
            print(json.dumps(asdict(report), sort_keys=True))
            if not report.applied:
                raise SystemExit(3)
            return

        if args.operation == "export":
            workspace.export_file(args.engagement_id, args.output)
            envelope = workspace.envelope(args.engagement_id)
            print(json.dumps({
                "engagement_id": args.engagement_id,
                "records": len(envelope.records),
                "output": str(Path(args.output)),
                "source_nights": sorted({
                    record.source_night for record in envelope.records
                }),
            }, sort_keys=True))
            return
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        _error(exc)
