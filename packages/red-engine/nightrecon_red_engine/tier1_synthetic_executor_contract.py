"""Fail-closed Tier 1 synthetic executor contract.

Fixture replay only. No process, socket, service API, or arbitrary callback.
This is a contract-test foundation, not a third-party tool adapter.
"""
from __future__ import annotations

import hashlib
import json
import re

from .tier1_capability_plan import TIER1, plan_tier1_tools


class SyntheticExecutionError(ValueError):
    """Rejected synthetic operation."""


def replay_tier1_fixture(
    *, engagement_id: str, tool: str, target: str,
    authorized_targets: tuple[str, ...], fixture: bytes,
    platform: str, prerequisite_attested: bool,
    authorization_record: str, approval_record: str | None,
    cancelled: bool = False, max_bytes: int = 65536,
) -> dict:
    """Replay a bounded fixture only when the engagement gate is complete.

    The replay is intentionally NOT a real executor: it cannot invoke binaries.
    """
    if (tool not in TIER1 or type(prerequisite_attested) is not bool
            or type(cancelled) is not bool or type(max_bytes) is not int
            or not 0 < max_bytes <= 65536
            or not isinstance(fixture, bytes) or not 0 < len(fixture) <= max_bytes
            or not isinstance(authorization_record, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", authorization_record)
            or (approval_record is not None and
                (not isinstance(approval_record, str) or not re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", approval_record)))):
        raise SyntheticExecutionError("Invalid replay contract or budget")
    try:
        plan = plan_tier1_tools(
            engagement_id=engagement_id, authorized_targets=authorized_targets,
            selected_tools=(tool,), available_tools={tool: prerequisite_attested},
            platform=platform, intrusive_approval=approval_record is not None,
        )
    except ValueError as exc:
        raise SyntheticExecutionError("Invalid engagement or scope") from exc
    if (cancelled or not prerequisite_attested or target not in authorized_targets
            or (TIER1[tool][1] and approval_record is None)):
        raise SyntheticExecutionError("Replay blocked by scope, approval, prerequisite or stop")
    try:
        data = json.loads(fixture)
    except (ValueError, UnicodeDecodeError) as exc:
        raise SyntheticExecutionError("Malformed synthetic fixture") from exc
    if (not isinstance(data, dict) or data.get("tool") != tool
            or data.get("target") != target or data.get("synthetic") is not True
            or not isinstance(data.get("observations"), list)
            or len(data["observations"]) > 256
            or any(not isinstance(row, dict) or set(row) != {"code"}
                   or type(row["code"]) is not int or not 0 <= row["code"] <= 999
                   for row in data["observations"])):
        raise SyntheticExecutionError("Invalid synthetic evidence")
    return {
        "schema": "red.tier1_synthetic_replay.v1",
        "engagement_id": engagement_id, "tool": tool, "target": target,
        "authorization_record": authorization_record,
        "approval_record": approval_record,
        "fixture_sha256": hashlib.sha256(fixture).hexdigest(),
        "observations": [{"code": row["code"], "classification": "synthetic_unverified"}
                         for row in data["observations"]],
        "synthetic": True, "external_execution": False,
        "integration_verified": False,
        "execution_allowed": False,
        "limitations": "Synthetic replay only; no real tool execution or target verification.",
    }
