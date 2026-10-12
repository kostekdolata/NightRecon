"""Governed in-process worker for bounded, pre-registered offline operations.

No subprocess, shell, sockets, or plugin loading. This is deliberately a
single-process prototype: FileEngagementPolicyStore is not a concurrent atomic
reservation service. Network-capable workers MUST NOT use it until that exists.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, TypeVar

from nightrecon_shared_core.engagement_policy import (
    FileEngagementPolicyStore, append_authorization_audit,
    evaluate_action, evaluate_reserved_action,
)

T = TypeVar("T")

@dataclass(frozen=True)
class OfflineOperation:
    name: str
    capability: str
    impact: str = "low"

@dataclass(frozen=True)
class OperationOutcome:
    name: str
    engagement_id: str
    target: str
    result: object

# Explicitly non-network operations only.
OFFLINE_OPERATIONS = {
    "inspect-imported-capture": OfflineOperation(
        "inspect-imported-capture", "external.tshark.inspect"
    ),
}

def run_offline_operation(
    *,
    operation: str,
    engagement_id: str,
    engagement_status: str,
    target: str,
    policy_store: FileEngagementPolicyStore,
    audit_path: str | Path,
    work: Callable[[], T],
    approved: bool = False,
) -> OperationOutcome:
    definition = OFFLINE_OPERATIONS.get(operation)
    if definition is None:
        raise ValueError("Unknown or network-capable operation")
    policy = policy_store.policy(engagement_id)
    if policy is None:
        raise PermissionError("Missing engagement policy")
    decision = evaluate_action(
        policy, engagement_status=engagement_status,
        capability=definition.capability, target=target,
        impact=definition.impact, approval_present=approved,
    )
    append_authorization_audit(audit_path, decision)
    if not decision.allowed:
        raise PermissionError(decision.reason_code)

    # Reserve the action before any user callback. Offline-only and
    # single-process: not sufficient for concurrent or network operations.
    policy_store.consume_action(engagement_id)
    current = policy_store.policy(engagement_id)
    if current is None:
        raise PermissionError("Engagement policy unavailable after reservation")
    renewed = evaluate_reserved_action(
        current, engagement_status=engagement_status,
        capability=definition.capability, target=target,
        impact=definition.impact, approval_present=approved,
    )
    append_authorization_audit(audit_path, renewed)
    if not renewed.allowed:
        raise PermissionError(renewed.reason_code)
    # work must be a trusted, pre-bound, offline function. Caller-supplied
    # untrusted callback execution is not supported as a security boundary.
    return OperationOutcome(operation, engagement_id, renewed.target, work())
