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
from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy
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

    policy = operations.add_parser("policy-set", help="Set fail-closed engagement execution policy.")
    policy.add_argument("root")
    policy.add_argument("--engagement-id", required=True)
    policy.add_argument("--scope", action="append", required=True)
    policy.add_argument("--valid-from", required=True)
    policy.add_argument("--valid-until", required=True)
    policy.add_argument("--max-actions", type=int, required=True)
    policy.add_argument("--capability", action="append", required=True)
    policy.add_argument("--approval-required", action="append", default=[])

    policy_show = operations.add_parser("policy-show", help="Show engagement execution policy.")
    policy_show.add_argument("root")
    policy_show.add_argument("--engagement-id", required=True)

    revoke = operations.add_parser("revoke", help="Revoke engagement execution authorization.")
    revoke.add_argument("root")
    revoke.add_argument("--engagement-id", required=True)

    authorize = operations.add_parser("authorize", help="Evaluate one action against engagement policy.")
    authorize.add_argument("root")
    authorize.add_argument("--engagement-id", required=True)
    authorize.add_argument("--capability", required=True)
    authorize.add_argument("--target", required=True)
    authorize.add_argument("--impact", choices=("low", "standard", "high"), default="standard")
    authorize.add_argument("--approved", action="store_true")
    authorize.add_argument("--consume", action="store_true")

    audit = operations.add_parser("audit", help="Show engagement authorization decision audit.")
    audit.add_argument("root")
    audit.add_argument("--engagement-id", required=True)

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

        if args.operation == "policy-set":
            policy = workspace.set_execution_policy(EngagementExecutionPolicy(
                engagement_id=args.engagement_id,
                scope=tuple(args.scope),
                valid_from=args.valid_from,
                valid_until=args.valid_until,
                max_actions=args.max_actions,
                permitted_capabilities=tuple(args.capability),
                approval_required_capabilities=tuple(args.approval_required),
            ))
            print(json.dumps(policy.to_dict(), sort_keys=True))
            return

        if args.operation == "policy-show":
            print(json.dumps(
                workspace.execution_policy(args.engagement_id).to_dict(),
                sort_keys=True,
            ))
            return

        if args.operation == "revoke":
            print(json.dumps(
                workspace.revoke_execution(args.engagement_id).to_dict(),
                sort_keys=True,
            ))
            return

        if args.operation == "authorize":
            print(json.dumps(asdict(workspace.authorize_action(
                args.engagement_id,
                capability=args.capability,
                target=args.target,
                impact=args.impact,
                approval_present=args.approved,
                consume=args.consume,
            )), sort_keys=True))
            return

        if args.operation == "audit":
            print(json.dumps(
                [asdict(item) for item in workspace.authorization_audit(args.engagement_id)],
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
