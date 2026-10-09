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
import signal
import subprocess
import threading
import time
from datetime import datetime, timezone

from nightrecon_shared_core.engagement_policy import (
    FileEngagementPolicyStore, evaluate_action, evaluate_reserved_action,
    append_authorization_audit,
)
from .atomic_action_ledger import AtomicActionLedger
from .governed_command_runner import FixedCommand, CommandOutcome
from .windows_job import WindowsJob


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
    cancel_event: threading.Event | None = None,
    poll_interval: float = 0.2,
) -> CommandOutcome:
    """Run a fixed low-impact diagnostic with shared-policy AND atomic-ledger checks.

    Assumes trusted command definitions and an already-provisioned ledger;
    the caller must synchronise ledger revocation and budget with shared policy.
    A separate privileged broker and continuously polled cancellation remain
    necessary before exposing network/elevated operations.
    """
    if not 0.05 <= poll_interval <= 1.0:
        raise ValueError("Invalid poll interval")
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
    ledger.reserve(engagement_id, action_id, policy_limit=policy.max_actions,\n                   policy_used=policy.actions_used, policy_revoked=policy.revoked)
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
    process = None
    job = None
    status = "error"
    return_code = None
    output = bytearray()
    errors = bytearray()
    readers = []
    deadline = time.monotonic() + command.timeout_seconds
    try:
        process = subprocess.Popen(
            [str(command.executable), *command.arguments],
            shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            start_new_session=(os.name == "posix"),
            creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0),
        )
        if os.name == "nt":
            try:
                job = WindowsJob(process)
            except BaseException:
                process.kill()
                process.wait()
                raise
        def drain(pipe, sink):
            try:
                while True:
                    chunk = pipe.read(8192)
                    if not chunk:
                        break
                    remaining = max(0, 65536 - len(sink))
                    if remaining:
                        sink.extend(chunk[:remaining])
            finally:
                pipe.close()
        for pipe, sink in ((process.stdout, output), (process.stderr, errors)):
            worker = threading.Thread(target=drain, args=(pipe, sink), daemon=True)
            worker.start()
            readers.append(worker)
        # Communicate in short intervals to permit cancellation and revalidation.
        # This worker has no process-tree containment and is not suitable for
        # tools which spawn child processes or generate unbounded output.
        while True:
            if cancel_event is not None and cancel_event.is_set():
                status = "cancelled"
                raise InterruptedError("Operation cancelled")
            fresh = FileEngagementPolicyStore(policy_store.path).policy(engagement_id)
            if fresh is None:
                status = "revoked"
                raise PermissionError("Engagement policy disappeared")
            check = evaluate_reserved_action(
                fresh, engagement_status=engagement_status,
                capability=command.capability, target=target,
                impact=command.impact, approval_present=approved,
            )
            if not check.allowed:
                status = "revoked"
                raise PermissionError(check.reason_code)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                status = "timeout"
                raise subprocess.TimeoutExpired(str(command.executable), command.timeout_seconds)
            try:
                return_code = process.wait(timeout=min(poll_interval, remaining))
                status = "completed"
                break
            except subprocess.TimeoutExpired:
                continue
    finally:
        if process is not None and process.poll() is None:
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                if job is not None:
                    job.close()  # KILL_ON_JOB_CLOSE terminates assigned descendants.
                else:
                    process.kill()
            process.wait()
        if job is not None:
            job.close()
        for worker in readers:
            worker.join(timeout=2)
        _record(result_audit_path, action_id=action_id, engagement_id=engagement_id,
                command=command.name, status=status, returncode=return_code)
    return CommandOutcome(
        command.name, return_code,
        bytes(output).decode("utf-8", "replace")[:65536],
        bytes(errors).decode("utf-8", "replace")[:65536],
    )
