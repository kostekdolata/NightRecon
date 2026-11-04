"""Governed, bounded OFFLINE TShark inspection.

No capture interfaces, shell, plugins, external targets or arbitrary flags.
The fixed executor's transactional engagement gate remains authoritative.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path

from .atomic_command_executor import execute_atomically_governed
from .governed_command_runner import FixedCommand
from .transactional_policy_authority import TransactionalPolicyAuthority
from .tshark_import import parse_tshark_json

MAX_CAPTURE_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class GovernedTsharkResult:
    action_id: str
    target: str
    returncode: int
    capture_sha256: str
    packet_count: int
    protocols: tuple[tuple[str, int], ...]

    def operator_report(self) -> dict:
        return {
            "tool": "tshark",
            "operation": "bounded-offline-capture-inspection",
            "action_id": self.action_id,
            "target": self.target,
            "command_exit_code": self.returncode,
            "execution_status": "succeeded" if self.returncode == 0 else "failed",
            "evidence_status": "unverified-observation",
            "capture_sha256": self.capture_sha256,
            "packets_observed": self.packet_count,
            "protocol_counts": dict(self.protocols),
            "limitations": [
                "Only up to the first five packets were inspected.",
                "Passive packet metadata is not proof of a vulnerability.",
                "No live network capture or scanning was performed.",
            ],
        }


def execute_governed_tshark_inspection(
    *, authority: TransactionalPolicyAuthority,
    engagement_id: str,
    action_id: str,
    target: str,
    executable: str | Path,
    trusted_sha256: str,
    capture_path: str | Path,
    capture_root: str | Path,
    audit_path: str | Path,
    result_audit_path: str | Path,
    enabled: bool = False,
) -> GovernedTsharkResult:
    """Inspect an existing bounded capture under a registered engagement.

    The operator must supply a trusted executable hash from independent
    release/installation provenance. File paths never confer authorisation.
    """
    if not enabled:
        raise PermissionError("Offline TShark execution requires explicit opt-in")
    root = Path(capture_root).resolve(strict=True)
    capture = Path(capture_path).resolve(strict=True)
    if not root.is_dir() or not capture.is_relative_to(root) or not capture.is_file():
        raise PermissionError("Capture must be a file within the approved capture directory")
    if capture.stat().st_size > MAX_CAPTURE_BYTES:
        raise ValueError("Capture exceeds bounded inspection size")
    program = Path(executable)
    if not program.is_absolute() or program.name.lower() not in ("tshark", "tshark.exe"):
        raise ValueError("TShark executable must be an absolute trusted executable")
    if not program.is_file():
        raise FileNotFoundError("Trusted TShark executable is unavailable")
    with program.open("rb") as handle:
        executable_digest = hashlib.file_digest(handle, "sha256").hexdigest()
    if executable_digest != trusted_sha256.lower():
        raise PermissionError("TShark executable digest mismatch")
    with capture.open("rb") as handle:
        capture_digest = hashlib.file_digest(handle, "sha256").hexdigest()
    command = FixedCommand(
        name="tshark-bounded-offline",
        executable=program,
        arguments=("-r", str(capture), "-n", "-c", "5", "-T", "json"),
        capability="external.tshark.inspect",
        impact="low", timeout_seconds=30,
        executable_sha256=trusted_sha256,
    )
    outcome = execute_atomically_governed(
        command=command,
        action_id=action_id,
        engagement_id=engagement_id,
        engagement_status="active",
        target=target,
        policy_store=None,
        ledger=None,
        authority=authority,
        audit_path=audit_path,
        result_audit_path=result_audit_path,
    )
    if outcome.returncode != 0:
        raise RuntimeError(f"Governed TShark failed with exit code {outcome.returncode}")
    summary = parse_tshark_json(outcome.stdout.encode("utf-8"))
    return GovernedTsharkResult(
        action_id, target, outcome.returncode, capture_digest,
        summary.packets, summary.protocols,
    )
