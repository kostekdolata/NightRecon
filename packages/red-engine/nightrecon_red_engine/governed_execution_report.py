"""Unified, bounded execution ledger report for governed Red Night tools.

Reads actual executor audit records, not inferred scan success. Handles
concurrent/interleaved action records, retains failure and incomplete states,
and never includes command arguments, stdout, stderr, credentials or secrets.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from pathlib import Path
import json

MAX_LEDGER_BYTES = 8 * 1024 * 1024
MAX_EVENTS = 20000
KNOWN_TOOLS = {
    "nmap-bounded-connect": "nmap",
    "nmap-tcp-connect": "nmap",
    "tshark-bounded-offline": "tshark",
    "nuclei-bounded-http-fingerprint": "nuclei",
}
SAFE_STATES = frozenset({
    "started", "completed", "failed", "error", "cancelled", "revoked",
    "timeout", "denied-after-reservation",
})


def summarize_governed_execution_ledger(
    path: str | Path, *, engagement_id: str | None = None,
) -> dict:
    """Reconcile independently executed actions in their actual event order.

    An absent terminal event remains incomplete. Unknown tools/states are
    preserved as unrecognised metadata, never classified as successful.
    """
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError("Governed execution ledger unavailable")
    if source.stat().st_size > MAX_LEDGER_BYTES:
        raise ValueError("Governed execution ledger exceeds report limit")
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    event_count = 0
    with source.open("rb") as handle:
        for line in handle:
            if not line.strip():
                continue
            event_count += 1
            if event_count > MAX_EVENTS or len(line) > 4096:
                raise ValueError("Governed execution ledger exceeds event limits")
            try:
                event = json.loads(line)
            except (UnicodeError, ValueError) as exc:
                raise ValueError("Invalid governed execution event") from exc
            if not isinstance(event, dict):
                raise ValueError("Invalid governed execution event")
            for key in ("action_id", "engagement_id", "command", "status", "recorded_at"):
                if not isinstance(event.get(key), str) or not 1 <= len(event[key]) <= 256:
                    raise ValueError("Invalid governed execution event metadata")
            try:
                datetime.fromisoformat(event["recorded_at"])
            except ValueError as exc:
                raise ValueError("Invalid governed execution event timestamp") from exc
            rc = event.get("returncode")
            if rc is not None and (type(rc) is not int or not -65535 <= rc <= 65535):
                raise ValueError("Invalid governed execution return code")
            if engagement_id is not None and event["engagement_id"] != engagement_id:
                continue
            groups[(event["engagement_id"], event["action_id"])].append({
                "command": event["command"], "status": event["status"],
                "returncode": rc, "recorded_at": event["recorded_at"],
            })
    actions = []
    for (engagement, action_id), events in sorted(groups.items()):
        names = {e["command"] for e in events}
        statuses = [e["status"] for e in events]
        terminal = events[-1]
        valid_sequence = (
            len(names) == 1 and statuses[0] == "started"
            and len(statuses) == 2
            and terminal["status"] in SAFE_STATES - {"started"}
        )
        if not valid_sequence:
            state = "incomplete-or-inconsistent"
        elif terminal["status"] == "completed" and terminal["returncode"] == 0:
            state = "succeeded"
        elif terminal["status"] in SAFE_STATES:
            state = "failed-or-interrupted"
        else:
            state = "unrecognised"
        command = events[0]["command"]
        actions.append({
            "engagement_id": engagement,
            "action_id": action_id,
            "tool": KNOWN_TOOLS.get(command, "unrecognised-tool"),
            "command_preset": command if command in KNOWN_TOOLS else "unrecognised-command",
            "execution_status": state,
            "returncode": terminal["returncode"] if valid_sequence else None,
            "events": tuple({"status": e["status"], "at": e["recorded_at"]} for e in events),
            "limitations": (
                "Execution status is not vulnerability confirmation.",
                "Unknown and incomplete actions require operator review.",
            ),
        })
    return {
        "report_type": "governed-tool-execution-ledger",
        "evidence_status": "executor-audit-metadata-only",
        "event_count": sum(len(v) for v in groups.values()),
        "action_count": len(actions),
        "successful_actions": sum(a["execution_status"] == "succeeded" for a in actions),
        "failed_or_incomplete_actions": sum(a["execution_status"] != "succeeded" for a in actions),
        "actions": tuple(actions),
        "limitations": (
            "Only actual recorded executor events are included.",
            "No arguments, raw process output, credentials or scan findings are included.",
            "Tool-specific findings require separate evidence review.",
        ),
    }
