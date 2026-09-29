"""Network-free CLI for the White Night control-plane foundation."""

from __future__ import annotations

import argparse
import json
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Sequence

from nightrecon_shared_core.editions import EDITIONS, edition_name

from nightrecon_white_engine.approval_engine import (
    ApprovalRequest,
    ApprovalWorkflow,
)
from nightrecon_white_engine.capabilities import (
    WHITE_ACTIVE_COMMANDS,
    WHITE_EDITION_SLUG,
    WHITE_OWNED_COMMANDS,
)
from nightrecon_white_engine.engagement_domain import EngagementDefinition
from nightrecon_white_engine.policy_compiler import (
    CompiledPolicyBundle,
    compile_engagement_policy,
)


def _version() -> str:
    try:
        return version("nightrecon-white-night")
    except PackageNotFoundError:
        return "0.1.0a4"


def _output_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--output",
        help="Optional destination for canonical JSON output.",
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
    approving.add_argument("--event-id", required=True)
    approving.add_argument("--actor-id", required=True)
    approving.add_argument("--at", required=True)
    approving.add_argument("--reason", required=True)
    _output_argument(approving)

    rejecting = approval_operations.add_parser(
        "reject",
        help="Append one eligible rejection decision.",
    )
    rejecting.add_argument("input")
    rejecting.add_argument("--event-id", required=True)
    rejecting.add_argument("--actor-id", required=True)
    rejecting.add_argument("--at", required=True)
    rejecting.add_argument("--reason", required=True)
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
    escalating.add_argument("--event-id", required=True)
    escalating.add_argument("--actor-id", required=True)
    escalating.add_argument("--at", required=True)
    escalating.add_argument("--reason", required=True)
    _output_argument(escalating)

    revoking = approval_operations.add_parser(
        "revoke",
        help="Revoke a currently valid approved workflow.",
    )
    revoking.add_argument("input")
    revoking.add_argument("--event-id", required=True)
    revoking.add_argument("--actor-id", required=True)
    revoking.add_argument("--at", required=True)
    revoking.add_argument("--reason", required=True)
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

    return parser


def _print_editions(as_json: bool) -> None:
    records = [edition.to_record() for edition in EDITIONS]
    if as_json:
        print(json.dumps(records, indent=2, sort_keys=True))
        return

    for edition in EDITIONS:
        availability = "available" if edition.standalone_available else "not yet available"
        print(f"{edition.name}: {edition.foundation_status}; standalone {availability}")


def _read_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def _emit(serialized: str, output_path: str | None = None) -> None:
    if output_path is not None:
        Path(output_path).write_text(serialized + "\n", encoding="utf-8")
    print(serialized)


def _compile_policy(input_path: str, output_path: str | None) -> None:
    payload = json.loads(_read_text(input_path))
    engagement = EngagementDefinition.from_dict(payload)
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
    payload = json.loads(_read_text(input_path))
    request = ApprovalRequest.from_dict(payload)
    workflow = ApprovalWorkflow.create(request, event_id=event_id)
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command is None:
            parser.print_help()
            print()
            print(f"{edition_name(WHITE_EDITION_SLUG)} foundation capabilities:")
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
                _create_approval(args.input, args.event_id, args.output)
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
                "approve", "reject", "delegate", "escalate", "revoke"
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

        parser.error("Command is not available in this edition.")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
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
)

assert WHITE_OWNED_COMMANDS == ("approval", "editions", "policy")
assert WHITE_ACTIVE_COMMANDS == ()
