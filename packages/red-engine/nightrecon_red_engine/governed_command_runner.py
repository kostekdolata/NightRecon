"""Governed, non-shell command runner for fixed administrative diagnostics.

Privileged execution is intentionally disabled until a separate operating-system
elevation broker is implemented. This runner accepts no shell strings or
user-supplied executable paths. Approved tool definitions contain absolute paths.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import subprocess
import hashlib

from nightrecon_shared_core.engagement_policy import (
    FileEngagementPolicyStore, append_authorization_audit,
    evaluate_action, evaluate_reserved_action,
)


@dataclass(frozen=True)
class FixedCommand:
    name: str
    executable: Path
    arguments: tuple[str, ...]
    capability: str
    impact: str = "low"
    timeout_seconds: int = 10
    elevated: bool = False
    executable_sha256: str | None = None

    def __post_init__(self):
        if self.executable_sha256 is not None and (len(self.executable_sha256) != 64 or any(c not in '0123456789abcdef' for c in self.executable_sha256.lower())):
            raise ValueError('Invalid pinned executable digest')
        if not self.executable.is_absolute():
            raise ValueError("Fixed command executable must be an absolute path")
        if not 1 <= self.timeout_seconds <= 60:
            raise ValueError("Command timeout must be between 1 and 60 seconds")
        if self.elevated:
            raise ValueError("Elevation requires a separate approved broker")
        if any(not isinstance(arg, str) or len(arg) > 512 for arg in self.arguments):
            raise ValueError("Invalid fixed command argument")


@dataclass(frozen=True)
class CommandOutcome:
    name: str
    returncode: int
    stdout: str
    stderr: str


def execute_fixed_command(
    *,
    command: FixedCommand,
    engagement_id: str,
    engagement_status: str,
    target: str,
    policy_store: FileEngagementPolicyStore,
    audit_path: str | Path,
    approved: bool = False,
) -> CommandOutcome:
    """Execute only a trusted fixed definition, fail closed and audit decisions.

    Intended for a single trusted local coordinator. File policy reservations
    are not atomic across processes; do not expose as a concurrent RPC endpoint.
    """
    if not command.executable.is_file():
        raise FileNotFoundError("Approved command executable is unavailable")
    if command.executable_sha256 is not None:
        with command.executable.open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != command.executable_sha256.lower():
                raise PermissionError('Executable has changed since approval')
    policy = policy_store.policy(engagement_id)
    if policy is None:
        raise PermissionError("Missing engagement execution policy")
    decision = evaluate_action(
        policy, engagement_status=engagement_status,
        capability=command.capability, target=target,
        impact=command.impact, approval_present=approved,
    )
    append_authorization_audit(audit_path, decision)
    if not decision.allowed:
        raise PermissionError(decision.reason_code)
    policy_store.consume_action(engagement_id)
    current = policy_store.policy(engagement_id)
    if current is None:
        raise PermissionError("Execution policy disappeared after reservation")
    final = evaluate_reserved_action(
        current, engagement_status=engagement_status,
        capability=command.capability, target=target,
        impact=command.impact, approval_present=approved,
    )
    append_authorization_audit(audit_path, final)
    if not final.allowed:
        raise PermissionError(final.reason_code)
    completed = subprocess.run(
        [str(command.executable), *command.arguments],
        shell=False,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=command.timeout_seconds,
        check=False,
    )
    return CommandOutcome(
        command.name, completed.returncode,
        completed.stdout[:65536], completed.stderr[:65536],
    )
