"""Opt-in governed Nmap scan-to-evidence coordinator.

Network execution is disabled by default. Enabling it requires an explicitly
registered active SQLite engagement, trusted Nmap binary hash and approved
capability. No unbounded scan parameters or shell entrypoint.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import threading
from .transactional_policy_authority import TransactionalPolicyAuthority
from .atomic_command_executor import execute_atomically_governed
from .nmap_governed_preset import bounded_nmap_tcp_connect
from .governed_nmap_evidence import parse_governed_nmap_result
from .nmap_import import NmapEvidence
from .managed_components import resolve_managed_component

@dataclass(frozen=True)
class GovernedScanResult:
    evidence: NmapEvidence
    command_returncode: int
    action_id: str = ""
    target: str = ""

    def operator_report(self) -> dict:
        """Describe observed results only; do not infer vulnerabilities or verification."""
        services = tuple(
            {"address": host.address, "protocol": service.protocol,
             "port": service.port, "state": service.state, "name": service.name}
            for host in self.evidence.hosts for service in host.services
        )
        return {
            "action_id": self.action_id, "target": self.target,
            "tool": "nmap", "operation": "bounded-tcp-connect",
            "command_exit_code": self.command_returncode,
            "execution_status": "succeeded" if self.command_returncode == 0 else "failed",
            "evidence_status": "unverified-observation",
            "observed_hosts": tuple(host.address for host in self.evidence.hosts),
            "services": services,
            "limitations": (
                "A completed scan does not prove exploitability or a vulnerability.",
                "Only the approved TCP ports 22, 80 and 443 were tested.",
            ),
        }

def execute_governed_nmap_discovery(
    *, authority: TransactionalPolicyAuthority,
    engagement_id: str, action_id: str, target: str,
    executable: str | Path, trusted_sha256: str,
    audit_path: str | Path, result_audit_path: str | Path,
    enabled: bool = False,
    cancel_event: threading.Event | None = None,
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
        cancel_event=cancel_event,
    )
    return GovernedScanResult(
        evidence=parse_governed_nmap_result(outcome=outcome, target=target),
        command_returncode=outcome.returncode,
        action_id=action_id, target=target,
    )


def execute_managed_nmap_discovery(
    *, authority: TransactionalPolicyAuthority,
    engagement_id: str, action_id: str, target: str,
    components_root: str | Path, manifest_path: str | Path,
    audit_path: str | Path, result_audit_path: str | Path,
    enabled: bool = False,
    cancel_event: threading.Event | None = None,
) -> GovernedScanResult:
    """Resolve only managed Nmap and then use the fixed governed scan preset."""
    if not enabled:
        raise PermissionError("Live managed Nmap discovery is disabled")
    component = resolve_managed_component(
        components_root=components_root, manifest_path=manifest_path,
        component_name="nmap")
    return execute_governed_nmap_discovery(
        authority=authority, engagement_id=engagement_id,
        action_id=action_id, target=target, executable=component.executable,
        trusted_sha256=component.sha256, audit_path=audit_path,
        result_audit_path=result_audit_path, enabled=True,
        cancel_event=cancel_event)
