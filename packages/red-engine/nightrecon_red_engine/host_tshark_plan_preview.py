"""Read-only preview of a governed offline TShark inspection.

Never captures live traffic, executes an external process, writes a plan,
or reserves an engagement action. Capture metadata is never scan authority.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sqlite3
import stat

from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy, evaluate_action
from .host_preflight import HostPreflightSnapshot, assess_tool_readiness
from .managed_components import resolve_managed_component
from .governed_tshark_coordinator import MAX_CAPTURE_BYTES

_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$")


def prepare_offline_tshark_plan(
    *, snapshot: HostPreflightSnapshot, target: str, capture_path: str | Path,
    capture_root: str | Path, engagement_id: str, action_id: str,
    authority_db: str | Path, components_root: str | Path,
    manifest_path: str | Path,
) -> dict:
    """Prepare one inert governed-batch task from an operator-selected existing capture."""
    if not isinstance(snapshot, HostPreflightSnapshot) or snapshot.schema != 1:
        raise ValueError("Host snapshot is unavailable or incompatible")
    try:
        observed = datetime.fromisoformat(snapshot.collected_at)
        if observed.tzinfo is None or observed.utcoffset() is None:
            raise ValueError("Naive timestamp")
    except (ValueError, TypeError, OverflowError) as exc:
        raise ValueError("Host snapshot has an invalid collection timestamp") from exc
    now = datetime.now(timezone.utc)
    if not (now - timedelta(minutes=5) <= observed <= now + timedelta(seconds=30)):
        raise ValueError("Host snapshot is stale or future-dated; refresh preflight")
    if not isinstance(target, str):
        raise ValueError("Explicit exact IPv4 attribution target required")
    try:
        selected = str(ipaddress.IPv4Address(target))
    except ValueError as exc:
        raise ValueError("Explicit exact IPv4 attribution target required") from exc
    if not all(isinstance(x, str) and _ID.fullmatch(x) for x in (engagement_id, action_id)):
        raise ValueError("Invalid engagement or action identifier")
    if not isinstance(capture_path, (str, Path)) or not isinstance(capture_root, (str, Path)):
        raise ValueError("Explicit capture and approved capture root required")
    root_path = Path(capture_root)
    selected_path = Path(capture_path)
    if selected_path.is_symlink():
        raise PermissionError("Symbolic-link capture files are not accepted")
    root = root_path.resolve(strict=True)
    capture = selected_path.resolve(strict=True)
    if not root.is_dir() or not capture.is_relative_to(root):
        raise PermissionError("Capture is outside the approved capture root")
    size = capture.stat()
    if not stat.S_ISREG(size.st_mode) or size.st_size == 0 or size.st_size > MAX_CAPTURE_BYTES:
        raise ValueError("Capture must be a nonempty bounded regular file")
    with capture.open("rb") as stream:
        capture_digest = hashlib.file_digest(stream, "sha256").hexdigest()

    readiness = assess_tool_readiness(snapshot, "tshark")
    candidate = readiness.get("tool_candidate") or {}
    if candidate.get("state") != "unverified-present" or not candidate.get("path"):
        raise FileNotFoundError("TShark candidate was not discovered")
    component = resolve_managed_component(
        components_root=components_root, manifest_path=manifest_path, component_name="tshark",
    )
    if Path(candidate["path"]).resolve(strict=True) != component.executable:
        raise PermissionError("Discovered TShark is not the approved managed component")

    database = Path(authority_db)
    if not database.is_file():
        raise FileNotFoundError("Registered engagement authority database required")
    with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True, timeout=2)) as db:
        row = db.execute(
            "SELECT policy_json, engagement_status, actions_used "
            "FROM engagement_authority WHERE engagement_id=?", (engagement_id,),
        ).fetchone()
    if row is None:
        raise PermissionError("Engagement not registered")
    data = json.loads(row[0])
    data["actions_used"] = row[2]
    policy = EngagementExecutionPolicy.from_dict(data)
    decision = evaluate_action(
        policy, engagement_status=row[1], capability="external.tshark.inspect",
        target=selected, impact="low", approval_present=False, now=now,
    )
    if not decision.allowed:
        raise PermissionError("Engagement policy denied preparation: " + decision.reason_code)
    return {
        "type": "inert-governed-plan-preview",
        "host_snapshot_at": snapshot.collected_at,
        "target_source": "explicit-operator-selected-attribution-ipv4",
        "approved_executable_source": "administrator-managed-component-manifest",
        "engagement_id": engagement_id,
        "execution_status": "not-started",
        "action_reserved": False,
        "fresh_authority_recheck_required": True,
        "execution_opt_in_required": True,
        "capture_sha256_at_preview": capture_digest,
        "plan": {"schema": 1, "tasks": [{
            "kind": "tshark", "engagement_id": engagement_id, "action_id": action_id,
            "target": selected, "executable": str(component.executable),
            "trusted_sha256": component.sha256,
            "capture_path": str(capture), "capture_root": str(root),
        }]},
        "limitations": [
            "The capture was selected, not generated or inspected; its contents have not been validated.",
            "Capture file digest is a point-in-time observation, not a guarantee of later integrity.",
            "No traffic capture, process execution, file mutation or reservation occurred.",
            "The executor must independently revalidate all policy, provenance and file constraints.",
        ],
    }
