"""Read-only presentation of real governed-command execution audit events.

This is an observation surface, not an execution scheduler. It never reads
command arguments, output bodies, credentials, or makes success assumptions.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path


MAX_AUDIT_BYTES = 4 * 1024 * 1024
MAX_EVENTS = 30
_TERMINAL = frozenset({"completed", "cancelled", "revoked", "timeout", "error", "denied-after-reservation"})


@dataclass(frozen=True)
class ExecutionTrace:
    action_id: str
    command: str
    status: str
    started_at: str | None
    finished_at: str | None
    returncode: int | None

    def describe(self) -> str:
        state = self.status
        if state == "completed":
            state = "succeeded" if self.returncode == 0 else "failed" if self.returncode is not None else "unknown-outcome"
        stamp = self.finished_at or self.started_at or "unknown-time"
        suffix = "" if self.returncode is None else f" exit={self.returncode}"
        return f"{stamp}  {self.command}  {state}  action={self.action_id}{suffix}"


def read_execution_trace(
    *, audit_path: str | Path, engagement_id: str, max_events: int = MAX_EVENTS,
) -> tuple[tuple[ExecutionTrace, ...], tuple[str, ...]]:
    """Read bounded, engagement-filtered event history; fail closed on corruption.

    Latest per-action status is derived from persisted event order, never from
    timestamp guesses. A lone started event is an *unconfirmed running state*:
    a crash may have left the audit incomplete.
    """
    if not engagement_id or not 1 <= max_events <= MAX_EVENTS:
        raise ValueError("Invalid engagement or trace limit")
    path = Path(audit_path)
    if not path.is_file():
        return (), ()
    warnings = []
    try:
        if path.stat().st_size > MAX_AUDIT_BYTES:
            return (), ("Audit file too large for bounded preview",)
        rows = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return (), ("Audit unavailable",)
    actions: dict[str, dict] = {}
    order: list[str] = []
    for row in rows:
        try:
            event = json.loads(row)
            if not isinstance(event, dict):
                raise ValueError("Not an object")
            if event.get("engagement_id") != engagement_id:
                continue
            action = event.get("action_id")
            command = event.get("command")
            status = event.get("status")
            if not isinstance(action, str) or not action.strip() or not isinstance(command, str) or not command.strip() or status not in _TERMINAL | {"started"}:
                raise ValueError("Invalid execution event")
            if len(action) > 128 or len(command) > 128:
                raise ValueError("Oversized event metadata")
            exit_code = event.get("returncode")
            if exit_code is not None and (isinstance(exit_code, bool) or not isinstance(exit_code, int)):
                raise ValueError("Invalid return code")
            recorded = event.get("recorded_at")
            timestamp = recorded if isinstance(recorded, str) and len(recorded) <= 80 else None
            if action not in actions:
                actions[action] = {"command": command, "started_at": None, "finished_at": None, "status": "unknown-outcome", "returncode": None}
                order.append(action)
            current = actions[action]
            if current["command"] != command or current["status"] in _TERMINAL:
                raise ValueError("Contradictory execution event")
            if status == "started":
                if current["started_at"] is not None:
                    raise ValueError("Duplicate start")
                current["started_at"] = timestamp
                current["status"] = "started"
            else:
                current["finished_at"] = timestamp
                current["status"] = status
                current["returncode"] = exit_code
        except (ValueError, TypeError, AttributeError):
            warnings.append("Malformed or contradictory audit line skipped")
    traces = tuple(
        ExecutionTrace(
            action_id=action, command=actions[action]["command"],
            status=actions[action]["status"],
            started_at=actions[action]["started_at"],
            finished_at=actions[action]["finished_at"],
            returncode=actions[action]["returncode"],
        )
        for action in order[-max_events:]
    )
    if any(t.status == "started" for t in traces):
        warnings.append("Started actions may have exited without a final audit event; running state is unconfirmed")
    return traces, tuple(dict.fromkeys(warnings))
