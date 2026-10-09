"""Opt-in governed Nmap scan-to-evidence coordinator.

Network execution is disabled by default. Enabling it requires an explicitly
registered active SQLite engagement, trusted Nmap binary hash and approved
capability. No unbounded scan parameters or shell entrypoint.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from .transactional_policy_authority import TransactionalPolicyAuthority
from .atomic_command_executor import execute_atomically_governed
from .nmap_governed_preset import bounded_nmap_tcp_connect
from .governed_nmap_evidence import parse_governed_nmap_result
from .nmap_import import NmapEvidence

@dataclass(frozen=True)
class GovernedScanResult:
    evidence: NmapEvidence
    command_returncode: int

def execute_governed_nmap_discovery(
    *, authority: TransactionalPolicyAuthority,
    engagement_id: str, action_id: str, target: str,
    executable: str | Path, trusted_sha256: str,
    audit_path: str | Path, result_audit_path: str | Path,
    enabled: bool = False,
) -> GovernedScanResult:
    """Run precisely one approved bounded TCP-connect discovery.

    Caller must deliberately enable execution; no automatic scanning.
    """
    if not enabled:
        raise PermissionError("Live Nmap discovery is disabled")
    command = bounded_nmap_tcp_connect(
        executable=executable, target=target, trusted_sha256=trusted_sha256)
    outcome = execute_atomically_governed(
        command=command, action_id=action_id, engagement_id=engagement_id,
        engagement_status="active", target=target, policy_store=None,
        ledger=None, authority=authority, audit_path=audit_path,
        result_audit_path=result_audit_path,
    )
    return GovernedScanResult(
        evidence=parse_governed_nmap_result(outcome=outcome, target=target),
        command_returncode=outcome.returncode,
    )
