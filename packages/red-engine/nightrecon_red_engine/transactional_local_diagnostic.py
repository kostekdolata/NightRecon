"""Explicit transactional execution entrypoint for local diagnostics.

No automatic migration, network scan, arbitrary executable or elevation.
The engagement must already exist in the transactional policy authority.
"""
from __future__ import annotations
from pathlib import Path

from .transactional_policy_authority import TransactionalPolicyAuthority
from .atomic_command_executor import execute_atomically_governed
from .local_diagnostics import get_local_diagnostic


def execute_transactional_local_diagnostic(
    *, authority: TransactionalPolicyAuthority,
    engagement_id: str, action_id: str, target: str,
    diagnostic_name: str, audit_path: str | Path,
    result_audit_path: str | Path,
):
    """Execute an allowlisted local command under current transactional policy.

    Legacy stores are deliberately unused in the transactional code path;
    temporary placeholders are created solely for compatibility with the
    existing executor signature.
    """
    command = get_local_diagnostic(diagnostic_name)
    return execute_atomically_governed(
        command=command, action_id=action_id, engagement_id=engagement_id,
        engagement_status="active", target=target,
        policy_store=None, ledger=None, authority=authority,
        audit_path=audit_path, result_audit_path=result_audit_path,
    )
