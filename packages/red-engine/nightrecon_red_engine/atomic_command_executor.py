"""Atomic-ledger backed execution for trusted fixed diagnostics.

Only works with an explicitly provisioned action ledger. The ledger is a
second enforcement gate, NOT a replacement for authoritative policy.
No elevation, shell strings or network-specific launch presets here.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import json
import os
import subprocess
from datetime import datetime, timezone

from nightrecon_shared_core.engagement_policy import (
    FileEngagementPolicyStore, evaluate_action, evaluate_reserved_action,
    append_authorization_audit,
)
from .atomic_action_ledger import AtomicActionLedger
from .governed_command_runner import FixedCommand, CommandOutcome


def _record(path: str | Path, *, action_id: str, engagement_id: str,
            command: str, status: str, returncode: int | None = None) -> None:
    """Append metadata-only execution outcome; never log output or arguments."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(action_id=action_id, engagement_id=engagement_id,
                   command=command, status=status, returncode=returncode,
                   recorded_at=datetime.now(timezone.utc).isoformat())
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def execute_atomically_governed(
    *, command: FixedCommand, action_id: str, engagement_id: str,
    engagement_status: str, target: str, policy_store: FileEngagementPolicyStore,
    ledger: AtomicActionLedger, audit_path: str | Path, result_audit_path: str | Path,
    approved: bool = False,
) -> CommandOutcome:
    """Run a fixed low-impact diagnostic with shared-policy AND atomic-ledger checks.

    Assumes trusted command definitions and an already-provisioned ledger;
    the caller must synchronise ledger revocation and budget with shared policy.
    A separate privileged broker and continuously polled cancellation remain
    necessary before exposing network/elevated operations.
    """
    if command.elevated:
        raise PermissionError("Elevated execution requires privileged broker")
    if not command.executable.is_file():
        raise FileNotFoundError("Approved executable unavailable")
    policy = policy_store.policy(engagement_id)
    if policy is None:
        raise PermissionError("Missing engagement policy")
    decision = evaluate_action(
        policy, engagement_status=engagement_status,
        capability=command.capability, target=target, impact=command.impact,
        approval_present=approved,
    )
    append_authorization_audit(audit_path, decision)
    if not decision.allowed:
        raise PermissionError(decision.reason_code)
    ledger.reserve(engagement_id, action_id)
    latest = policy_store.policy(engagement_id)
    if latest is None:
        raise PermissionError("Engagement policy unavailable after reservation")
    final = evaluate_reserved_action(
        latest, engagement_status=engagement_status,
        capability=command.capability, target=target, impact=command.impact,
        approval_present=approved,
    )
    append_authorization_audit(audit_path, final)
    if not final.allowed:
        _record(result_audit_path, action_id=action_id, engagement_id=engagement_id,
                command=command.name, status="denied-after-reservation")
        raise PermissionError(final.reason_code)
    _record(result_audit_path, action_id=action_id, engagement_id=engagement_id,
            command=command.name, status="started")
    try:
        completed = subprocess.run(
            [str(command.executable), *command.arguments],
            shell=False, capture_output=True, text=True, errors="replace",
            timeout=command.timeout_seconds, check=False,
        )
    except subprocess.TimeoutExpired:
        _record(result_audit_path, action_id=action_id, engagement_id=engagement_id,
                command=command.name, status="timeout")
        raise
    except Exception:
        _record(result_audit_path, action_id=action_id, engagement_id=engagement_id,
                command=command.name, status="error")
        raise
    _record(result_audit_path, action_id=action_id, engagement_id=engagement_id,
            command=command.name, status="completed", returncode=completed.returncode)
    return CommandOutcome(command.name, completed.returncode,
                          completed.stdout[:65536], completed.stderr[:65536])
