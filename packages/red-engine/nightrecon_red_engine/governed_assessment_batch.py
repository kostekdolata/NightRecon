"""Bounded concurrent execution of known governed Nmap/TShark tasks.

This is an in-process coordinator, not an arbitrary command/job engine.
Actual actions are performed solely by existing transactional executors;
every task retains its own independently authorised engagement/action ID.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import threading
from typing import Callable

from .governed_nmap_coordinator import execute_governed_nmap_discovery
from .governed_tshark_coordinator import execute_governed_tshark_inspection
from .transactional_policy_authority import TransactionalPolicyAuthority


@dataclass(frozen=True)
class GovernedAssessmentTask:
    kind: str  # Precisely "nmap" or "tshark"; never a program name from user input.
    engagement_id: str
    action_id: str
    target: str
    executable: str | Path
    trusted_sha256: str
    audit_path: str | Path
    result_audit_path: str | Path
    capture_path: str | Path | None = None
    capture_root: str | Path | None = None


@dataclass(frozen=True)
class GovernedTaskEvent:
    action_id: str
    kind: str
    status: str
    recorded_at: str


@dataclass(frozen=True)
class GovernedTaskResult:
    action_id: str
    kind: str
    status: str
    report: dict | None
    reason_code: str | None


@dataclass(frozen=True)
class GovernedBatchResult:
    tasks: tuple[GovernedTaskResult, ...]
    events: tuple[GovernedTaskEvent, ...]

    def operator_report(self) -> dict:
        return {
            "operation": "bounded-concurrent-governed-assessment",
            "tasks": [
                {"action_id": t.action_id, "tool": t.kind, "status": t.status,
                 "reason_code": t.reason_code, "report": t.report}
                for t in self.tasks
            ],
            "events": [
                {"action_id": e.action_id, "tool": e.kind, "status": e.status,
                 "recorded_at": e.recorded_at}
                for e in self.events
            ],
            "summary": {
                name: sum(t.status == name for t in self.tasks)
                for name in ("succeeded", "failed", "blocked", "cancelled", "timed-out")
            },
        }


def run_governed_assessment_batch(
    *,
    authority: TransactionalPolicyAuthority,
    tasks: tuple[GovernedAssessmentTask, ...],
    enabled: bool = False,
    max_workers: int = 2,
    cancel_event: threading.Event | None = None,
    on_event: Callable[[GovernedTaskEvent], None] | None = None,
) -> GovernedBatchResult:
    if not enabled:
        raise PermissionError("Concurrent tool execution requires explicit opt-in")
    if not 1 <= max_workers <= 4 or not 1 <= len(tasks) <= 8:
        raise ValueError("Batch size or concurrency exceeds approved bounds")
    keys = [(t.engagement_id, t.action_id) for t in tasks]
    if len(set(keys)) != len(keys):
        raise ValueError("Duplicate action identifiers in batch")
    for task in tasks:
        if (task.kind not in ("nmap", "tshark") or not task.engagement_id
            or not task.action_id or len(task.action_id) > 128 or not task.target):
            raise ValueError("Unsupported or incomplete governed task")
        if task.kind == "tshark" and (task.capture_path is None or task.capture_root is None):
            raise ValueError("Offline TShark requires capture path and approved root")
        if task.kind == "nmap" and (task.capture_path is not None or task.capture_root is not None):
            raise ValueError("Nmap cannot accept capture parameters")
    stop = cancel_event if cancel_event is not None else threading.Event()
    guard = threading.Lock()
    events: list[GovernedTaskEvent] = []
    locks = {
        (t.engagement_id, t.target): threading.Lock() for t in tasks
    }

    def emit(task: GovernedAssessmentTask, status: str) -> None:
        item = GovernedTaskEvent(
            action_id=task.action_id, kind=task.kind, status=status,
            recorded_at=datetime.now(timezone.utc).isoformat(),
        )
        with guard:
            events.append(item)
        if on_event is not None:
            # Operator callback is local presentation only. Its failure must
            # never turn an executed command into an incorrectly failed action.
            try:
                on_event(item)
            except Exception:
                pass

    def execute(task: GovernedAssessmentTask) -> GovernedTaskResult:
        with locks[task.engagement_id, task.target]:
            if stop.is_set():
                emit(task, "cancelled")
                return GovernedTaskResult(task.action_id, task.kind, "cancelled", None, "cancel_requested")
            emit(task, "running")
            try:
                common = dict(
                    authority=authority, engagement_id=task.engagement_id,
                    action_id=task.action_id, target=task.target,
                    executable=task.executable, trusted_sha256=task.trusted_sha256,
                    audit_path=task.audit_path,
                    result_audit_path=task.result_audit_path,
                    enabled=True, cancel_event=stop,
                )
                if task.kind == "nmap":
                    outcome = execute_governed_nmap_discovery(**common)
                else:
                    common.update(
                        capture_path=task.capture_path, capture_root=task.capture_root,
                    )
                    outcome = execute_governed_tshark_inspection(**common)
                result = GovernedTaskResult(
                    task.action_id, task.kind, "succeeded",
                    outcome.operator_report(), None,
                )
            except InterruptedError:
                result = GovernedTaskResult(
                    task.action_id, task.kind, "cancelled", None, "cancel_requested",
                )
            except subprocess.TimeoutExpired:
                result = GovernedTaskResult(
                    task.action_id, task.kind, "timed-out", None, "tool_timeout",
                )
            except (PermissionError, FileNotFoundError, ValueError):
                result = GovernedTaskResult(
                    task.action_id, task.kind, "blocked", None, "preflight_or_policy_denied",
                )
            except Exception:
                result = GovernedTaskResult(
                    task.action_id, task.kind, "failed", None, "execution_or_evidence_failed",
                )
            emit(task, result.status)
            return result

    for task in tasks:
        emit(task, "queued")
    indexed: dict[int, GovernedTaskResult] = {}
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="rednight-governed") as pool:
        futures = {pool.submit(execute, task): i for i, task in enumerate(tasks)}
        try:
            for future in as_completed(futures):
                indexed[futures[future]] = future.result()
        except KeyboardInterrupt:
            stop.set()
            # Executor shutdown blocks until the existing atomic commands
            # observe cancellation and terminate their process groups.
            raise
    return GovernedBatchResult(
        tasks=tuple(indexed[i] for i in range(len(tasks))),
        events=tuple(events),
    )
