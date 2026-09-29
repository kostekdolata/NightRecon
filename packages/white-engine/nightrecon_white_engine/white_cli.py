"""Network-free CLI for the White Night control-plane foundation."""

from __future__ import annotations

import argparse
import json
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Sequence

from nightrecon_shared_core.contracts import EvidenceRecord
from nightrecon_shared_core.editions import EDITIONS, edition_name

from nightrecon_white_engine.approval_engine import (
    ApprovalRequest,
    ApprovalWorkflow,
)
from nightrecon_white_engine.audit_log import (
    AuditTrail,
    render_audit_summary,
)
from nightrecon_white_engine.capabilities import (
    WHITE_ACTIVE_COMMANDS,
    WHITE_EDITION_SLUG,
    WHITE_OWNED_COMMANDS,
)
from nightrecon_white_engine.engagement_domain import EngagementDefinition
from nightrecon_white_engine.evidence_custody import (
    EvidenceCustodyCase,
    EvidenceExportBundle,
    render_custody_summary,
)
from nightrecon_white_engine.policy_compiler import (
    CompiledPolicyBundle,
    compile_engagement_policy,
)


def _version() -> str:
    try:
        return version("nightrecon-white-night")
    except PackageNotFoundError:
        return "0.1.0a5"


def _output_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--output",
        help="Optional destination for canonical JSON output.",
    )


def _decision_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--event-id", required=True)
    parser.add_argument("--actor-id", required=True)
    parser.add_argument("--at", required=True)
    parser.add_argument("--reason", required=True)


def _audit_event_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--event-id", required=True)
    parser.add_argument("--event-type", required=True)
    parser.add_argument("--at", required=True)
    parser.add_argument("--actor-id", required=True)
    parser.add_argument("--subject-type", required=True)
    parser.add_argument("--subject-id", required=True)
    parser.add_argument(
        "--outcome",
        required=True,
        choices=("info", "success", "denied", "error"),
    )
    parser.add_argument("--reason-code", required=True)
    parser.add_argument("--summary", required=True)
    parser.add_argument(
        "--detail",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Optional secret-free audit detail; repeat as needed.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="white-night-app",
        description=(
            "NightRecon White Night command boundary. "
            "Current operations are local and network-free."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"White Night {_version()}",
    )

    subparsers = parser.add_subparsers(dest="command", title="commands")

    editions_parser = subparsers.add_parser(
        "editions",
        help="Show the NightRecon product catalog and readiness state.",
    )
    editions_parser.add_argument(
        "--json",
        action="store_true",
        help="Output the edition catalog as JSON.",
    )

    policy_parser = subparsers.add_parser(
        "policy",
        help="Compile or verify a local White Night policy bundle.",
    )
    policy_operations = policy_parser.add_subparsers(
        dest="policy_operation",
        required=True,
    )

    compiling = policy_operations.add_parser(
        "compile",
        help="Compile an engagement definition into shared-core policy.",
    )
    compiling.add_argument("input", help="Engagement definition JSON file.")
    _output_argument(compiling)

    verifying = policy_operations.add_parser(
        "verify",
        help="Verify fingerprints and structure of a compiled policy bundle.",
    )
    verifying.add_argument("input", help="Compiled policy bundle JSON file.")

    approval_parser = subparsers.add_parser(
        "approval",
        help="Create, advance, inspect, or verify a local approval workflow.",
    )
    approval_operations = approval_parser.add_subparsers(
        dest="approval_operation",
        required=True,
    )

    creating = approval_operations.add_parser(
        "create",
        help="Create an immutable approval workflow from a request JSON file.",
    )
    creating.add_argument("input", help="Approval request JSON file.")
    creating.add_argument("--event-id", required=True)
    _output_argument(creating)

    status = approval_operations.add_parser(
        "status",
        help="Project approval state at an explicit timestamp.",
    )
    status.add_argument("input", help="Approval workflow JSON file.")
    status.add_argument("--at", required=True)

    approving = approval_operations.add_parser(
        "approve",
        help="Append one eligible approval decision.",
    )
    approving.add_argument("input")
    _decision_arguments(approving)
    _output_argument(approving)

    rejecting = approval_operations.add_parser(
        "reject",
        help="Append one eligible rejection decision.",
    )
    rejecting.add_argument("input")
    _decision_arguments(rejecting)
    _output_argument(rejecting)

    delegating = approval_operations.add_parser(
        "delegate",
        help="Delegate direct eligible authority for this request only.",
    )
    delegating.add_argument("input")
    delegating.add_argument("--event-id", required=True)
    delegating.add_argument("--delegator-id", required=True)
    delegating.add_argument("--delegate-id", required=True)
    delegating.add_argument("--delegated-role", required=True)
    delegating.add_argument("--at", required=True)
    delegating.add_argument("--valid-until", required=True)
    delegating.add_argument("--reason", required=True)
    _output_argument(delegating)

    escalating = approval_operations.add_parser(
        "escalate",
        help="Record one due approval escalation.",
    )
    escalating.add_argument("input")
    _decision_arguments(escalating)
    _output_argument(escalating)

    revoking = approval_operations.add_parser(
        "revoke",
        help="Revoke a currently valid approved workflow.",
    )
    revoking.add_argument("input")
    _decision_arguments(revoking)
    _output_argument(revoking)

    granting = approval_operations.add_parser(
        "grant",
        help="Render the exact action-bound approval grant when valid.",
    )
    granting.add_argument("input")
    granting.add_argument("--at", required=True)

    approval_verify = approval_operations.add_parser(
        "verify",
        help="Verify request, event-chain, and workflow fingerprints.",
    )
    approval_verify.add_argument("input")

    evidence_parser = subparsers.add_parser(
        "evidence",
        help="Manage local evidence custody and integrity artifacts.",
    )
    evidence_operations = evidence_parser.add_subparsers(
        dest="evidence_operation",
        required=True,
    )

    evidence_create = evidence_operations.add_parser(
        "create",
        help="Create a custody case from engagement policy and one evidence record.",
    )
    evidence_create.add_argument("engagement")
    evidence_create.add_argument("record")
    evidence_create.add_argument("--case-id", required=True)
    evidence_create.add_argument("--event-id", required=True)
    evidence_create.add_argument("--actor-id", required=True)
    evidence_create.add_argument("--custodian-id", required=True)
    evidence_create.add_argument("--at", required=True)
    evidence_create.add_argument("--reason", required=True)
    evidence_create.add_argument("--classification")
    _output_argument(evidence_create)

    evidence_add = evidence_operations.add_parser(
        "add",
        help="Add an ingested or derived record to an existing custody case.",
    )
    evidence_add.add_argument("input")
    evidence_add.add_argument("record")
    evidence_add.add_argument("--event-id", required=True)
    evidence_add.add_argument("--actor-id", required=True)
    evidence_add.add_argument("--custodian-id", required=True)
    evidence_add.add_argument("--at", required=True)
    evidence_add.add_argument("--reason", required=True)
    evidence_add.add_argument("--classification")
    evidence_add.add_argument(
        "--parent-evidence-id",
        action="append",
        default=[],
    )
    _output_argument(evidence_add)

    evidence_transfer = evidence_operations.add_parser(
        "transfer",
        help="Record a custody handoff for one evidence item.",
    )
    evidence_transfer.add_argument("input")
    evidence_transfer.add_argument("--evidence-id", required=True)
    evidence_transfer.add_argument("--event-id", required=True)
    evidence_transfer.add_argument("--actor-id", required=True)
    evidence_transfer.add_argument("--to-custodian", required=True)
    evidence_transfer.add_argument("--at", required=True)
    evidence_transfer.add_argument("--reason", required=True)
    _output_argument(evidence_transfer)

    evidence_manifest = evidence_operations.add_parser(
        "manifest",
        help="Generate a metadata-only integrity manifest.",
    )
    evidence_manifest.add_argument("input")
    evidence_manifest.add_argument("--at", required=True)

    evidence_export = evidence_operations.add_parser(
        "export",
        help="Create a governed portable evidence export bundle.",
    )
    evidence_export.add_argument("input")
    evidence_export.add_argument("--event-id", required=True)
    evidence_export.add_argument("--actor-id", required=True)
    evidence_export.add_argument("--destination", required=True)
    evidence_export.add_argument("--at", required=True)
    evidence_export.add_argument("--reason", required=True)
    evidence_export.add_argument(
        "--case-output",
        help="Optional destination for the updated post-export custody case.",
    )
    _output_argument(evidence_export)

    evidence_verify = evidence_operations.add_parser(
        "verify",
        help="Verify a custody case or evidence export bundle.",
    )
    evidence_verify.add_argument("input")

    evidence_summary = evidence_operations.add_parser(
        "summary",
        help="Render a secret-safe custody summary.",
    )
    evidence_summary.add_argument("input")
    evidence_summary.add_argument("--at", required=True)

    audit_parser = subparsers.add_parser(
        "audit",
        help="Create, append, inspect, or verify a tamper-evident audit trail.",
    )
    audit_operations = audit_parser.add_subparsers(
        dest="audit_operation",
        required=True,
    )

    audit_create = audit_operations.add_parser(
        "create",
        help="Create a logical audit trail with its first event.",
    )
    audit_create.add_argument("--trail-id", required=True)
    audit_create.add_argument("--engagement-id", required=True)
    _audit_event_arguments(audit_create)
    _output_argument(audit_create)

    audit_append = audit_operations.add_parser(
        "append",
        help="Append one immutable event to an audit trail.",
    )
    audit_append.add_argument("input")
    _audit_event_arguments(audit_append)
    _output_argument(audit_append)

    audit_verify = audit_operations.add_parser(
        "verify",
        help="Verify the audit hash chain and trail fingerprint.",
    )
    audit_verify.add_argument("input")

    audit_summary = audit_operations.add_parser(
        "summary",
        help="Render a secret-safe audit summary without event details.",
    )
    audit_summary.add_argument("input")

    return parser


def _print_editions(as_json: bool) -> None:
    records = [edition.to_record() for edition in EDITIONS]
    if as_json:
        print(json.dumps(records, indent=2, sort_keys=True))
        return
    for edition in EDITIONS:
        availability = (
            "available"
            if edition.standalone_available
            else "not yet available"
        )
        print(
            f"{edition.name}: {edition.foundation_status}; "
            f"standalone {availability}"
        )


def _read_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def _read_json(path: str) -> dict:
    payload = json.loads(_read_text(path))
    if not isinstance(payload, dict):
        raise ValueError("input JSON must be an object")
    return payload


def _emit(serialized: str, output_path: str | None = None) -> None:
    if output_path is not None:
        Path(output_path).write_text(
            serialized + "\n",
            encoding="utf-8",
        )
    print(serialized)


def _details(values: list[str]) -> tuple[tuple[str, str], ...]:
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for value in values:
        if "=" not in value:
            raise ValueError("audit detail must use KEY=VALUE")
        key, item = value.split("=", 1)
        if not key or not item:
            raise ValueError("audit detail must use nonblank KEY=VALUE")
        if key in seen:
            raise ValueError("audit detail keys must be unique")
        seen.add(key)
        pairs.append((key, item))
    return tuple(pairs)


def _compile_policy(input_path: str, output_path: str | None) -> None:
    engagement = EngagementDefinition.from_dict(_read_json(input_path))
    bundle = compile_engagement_policy(engagement)
    _emit(bundle.to_json(), output_path)


def _verify_policy(input_path: str) -> None:
    bundle = CompiledPolicyBundle.from_json(_read_text(input_path))
    print(json.dumps(
        {
            "bundle_fingerprint": bundle.bundle_fingerprint,
            "engagement_id": bundle.engagement_id,
            "integrity": "valid",
            "policy_fingerprint": bundle.policy_fingerprint,
        },
        sort_keys=True,
    ))


def _read_workflow(input_path: str) -> ApprovalWorkflow:
    return ApprovalWorkflow.from_json(_read_text(input_path))


def _create_approval(
    input_path: str,
    event_id: str,
    output_path: str | None,
) -> None:
    request = ApprovalRequest.from_dict(_read_json(input_path))
    workflow = ApprovalWorkflow.create(
        request,
        event_id=event_id,
    )
    _emit(workflow.to_json(), output_path)


def _mutate_approval(args: argparse.Namespace) -> None:
    workflow = _read_workflow(args.input)
    operation = args.approval_operation
    if operation == "approve":
        updated = workflow.approve(
            event_id=args.event_id,
            actor_id=args.actor_id,
            occurred_at=args.at,
            reason=args.reason,
        )
    elif operation == "reject":
        updated = workflow.reject(
            event_id=args.event_id,
            actor_id=args.actor_id,
            occurred_at=args.at,
            reason=args.reason,
        )
    elif operation == "delegate":
        updated = workflow.delegate(
            event_id=args.event_id,
            delegator_id=args.delegator_id,
            delegate_id=args.delegate_id,
            delegated_role=args.delegated_role,
            occurred_at=args.at,
            valid_until=args.valid_until,
            reason=args.reason,
        )
    elif operation == "escalate":
        updated = workflow.escalate(
            event_id=args.event_id,
            actor_id=args.actor_id,
            occurred_at=args.at,
            reason=args.reason,
        )
    elif operation == "revoke":
        updated = workflow.revoke(
            event_id=args.event_id,
            actor_id=args.actor_id,
            occurred_at=args.at,
            reason=args.reason,
        )
    else:
        raise ValueError("unsupported approval mutation")
    _emit(updated.to_json(), args.output)


def _read_case(path: str) -> EvidenceCustodyCase:
    return EvidenceCustodyCase.from_json(_read_text(path))


def _evidence_command(args: argparse.Namespace) -> None:
    operation = args.evidence_operation

    if operation == "create":
        engagement = EngagementDefinition.from_dict(
            _read_json(args.engagement)
        )
        record = EvidenceRecord.from_dict(_read_json(args.record))
        case = EvidenceCustodyCase.create(
            case_id=args.case_id,
            engagement_id=engagement.engagement_id,
            data_handling=engagement.roe.data_handling,
            record=record,
            actor_id=args.actor_id,
            custodian_id=args.custodian_id,
            occurred_at=args.at,
            event_id=args.event_id,
            reason=args.reason,
            classification=args.classification,
        )
        _emit(case.to_json(), args.output)
        return

    if operation == "add":
        case = _read_case(args.input)
        record = EvidenceRecord.from_dict(_read_json(args.record))
        updated = case.add_record(
            record,
            actor_id=args.actor_id,
            custodian_id=args.custodian_id,
            occurred_at=args.at,
            event_id=args.event_id,
            reason=args.reason,
            parent_evidence_ids=tuple(args.parent_evidence_id),
            classification=args.classification,
        )
        _emit(updated.to_json(), args.output)
        return

    if operation == "transfer":
        case = _read_case(args.input)
        updated = case.transfer(
            args.evidence_id,
            actor_id=args.actor_id,
            to_custodian=args.to_custodian,
            occurred_at=args.at,
            event_id=args.event_id,
            reason=args.reason,
        )
        _emit(updated.to_json(), args.output)
        return

    if operation == "manifest":
        case = _read_case(args.input)
        print(json.dumps(
            case.manifest(generated_at=args.at).to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        ))
        return

    if operation == "export":
        case = _read_case(args.input)
        updated, bundle = case.export(
            actor_id=args.actor_id,
            destination=args.destination,
            occurred_at=args.at,
            event_id=args.event_id,
            reason=args.reason,
        )
        if args.case_output is not None:
            Path(args.case_output).write_text(
                updated.to_json() + "\n",
                encoding="utf-8",
            )
        _emit(bundle.to_json(), args.output)
        return

    if operation == "verify":
        payload = _read_json(args.input)
        if "bundle_fingerprint" in payload:
            bundle = EvidenceExportBundle.from_dict(payload)
            result = {
                "artifact": "evidence-export-bundle",
                "engagement_id": bundle.case.engagement_id,
                "fingerprint": bundle.fingerprint,
                "integrity": "valid",
                "authorization_effect": "none",
            }
        else:
            case = EvidenceCustodyCase.from_dict(payload)
            result = {
                "artifact": "evidence-custody-case",
                "engagement_id": case.engagement_id,
                "fingerprint": case.fingerprint,
                "integrity": "valid",
                "authorization_effect": "none",
            }
        print(json.dumps(result, sort_keys=True))
        return

    if operation == "summary":
        print(render_custody_summary(
            _read_case(args.input),
            at=args.at,
        ))
        return

    raise ValueError("unsupported evidence operation")


def _audit_kwargs(args: argparse.Namespace) -> dict:
    return {
        "event_id": args.event_id,
        "event_type": args.event_type,
        "occurred_at": args.at,
        "actor_id": args.actor_id,
        "subject_type": args.subject_type,
        "subject_id": args.subject_id,
        "outcome": args.outcome,
        "reason_code": args.reason_code,
        "summary": args.summary,
        "details": _details(args.detail),
    }


def _audit_command(args: argparse.Namespace) -> None:
    operation = args.audit_operation
    if operation == "create":
        trail = AuditTrail.create(
            trail_id=args.trail_id,
            engagement_id=args.engagement_id,
            **_audit_kwargs(args),
        )
        _emit(trail.to_json(), args.output)
        return
    if operation == "append":
        trail = AuditTrail.from_json(_read_text(args.input))
        updated = trail.append(**_audit_kwargs(args))
        _emit(updated.to_json(), args.output)
        return
    if operation == "verify":
        trail = AuditTrail.from_json(_read_text(args.input))
        print(json.dumps({
            "engagement_id": trail.engagement_id,
            "integrity": "valid",
            "trail_fingerprint": trail.fingerprint,
            "trail_id": trail.trail_id,
        }, sort_keys=True))
        return
    if operation == "summary":
        print(render_audit_summary(
            AuditTrail.from_json(_read_text(args.input))
        ))
        return
    raise ValueError("unsupported audit operation")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command is None:
            parser.print_help()
            print()
            print(
                f"{edition_name(WHITE_EDITION_SLUG)} "
                "foundation capabilities:"
            )
            for capability in WHITE_FOUNDATION_CAPABILITIES_FOR_DISPLAY:
                print(f"  - {capability}")
            print("Active commands: none")
            return 0

        if args.command == "editions":
            _print_editions(args.json)
            return 0

        if args.command == "policy" and args.policy_operation == "compile":
            _compile_policy(args.input, args.output)
            return 0

        if args.command == "policy" and args.policy_operation == "verify":
            _verify_policy(args.input)
            return 0

        if args.command == "approval":
            if args.approval_operation == "create":
                _create_approval(
                    args.input,
                    args.event_id,
                    args.output,
                )
                return 0
            if args.approval_operation == "status":
                workflow = _read_workflow(args.input)
                print(json.dumps({
                    "request_id": workflow.request.request_id,
                    "status": workflow.status(args.at),
                    "workflow_fingerprint": workflow.fingerprint,
                }, sort_keys=True))
                return 0
            if args.approval_operation in {
                "approve",
                "reject",
                "delegate",
                "escalate",
                "revoke",
            }:
                _mutate_approval(args)
                return 0
            if args.approval_operation == "grant":
                workflow = _read_workflow(args.input)
                print(json.dumps(
                    workflow.grant(args.at).to_dict(),
                    sort_keys=True,
                    separators=(",", ":"),
                ))
                return 0
            if args.approval_operation == "verify":
                workflow = _read_workflow(args.input)
                print(json.dumps({
                    "integrity": "valid",
                    "request_id": workflow.request.request_id,
                    "workflow_fingerprint": workflow.fingerprint,
                }, sort_keys=True))
                return 0

        if args.command == "evidence":
            _evidence_command(args)
            return 0

        if args.command == "audit":
            _audit_command(args)
            return 0

        parser.error("Command is not available in this edition.")
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        parser.error(str(exc))
    return 2


WHITE_FOUNDATION_CAPABILITIES_FOR_DISPLAY = (
    "independent package boundary",
    "shared-core policy consumer",
    "standalone deployment target",
    "composed full-stack deployment target",
    "Live USB deployment target",
    "deterministic local ROE-to-policy compilation",
    "immutable approval workflow engine",
    "evidence custody and integrity manifests",
    "tamper-evident logical audit",
)

assert WHITE_OWNED_COMMANDS == (
    "approval",
    "audit",
    "editions",
    "evidence",
    "policy",
)
assert WHITE_ACTIVE_COMMANDS == ()
