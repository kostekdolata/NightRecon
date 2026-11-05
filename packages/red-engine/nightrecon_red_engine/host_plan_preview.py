"""Read-only, operator-selected host Nmap plan preparation.

A passive host snapshot provides evidence of which local interface addresses
exist, but never authorises them. The engagement policy and administrator-
pinned managed-component manifest must both independently validate the
selected target and executable. This module never launches a process, reserves
an action, or writes an engagement/plan file.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
import ipaddress
import json
from pathlib import Path
import re
import sqlite3

from nightrecon_shared_core.engagement_policy import (
    EngagementExecutionPolicy, evaluate_action,
)
from .host_preflight import HostPreflightSnapshot, assess_tool_readiness
from .managed_components import resolve_managed_component

_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$")


def prepare_local_nmap_plan(
    *,
    snapshot: HostPreflightSnapshot,
    target: str,
    engagement_id: str,
    action_id: str,
    authority_db: str | Path,
    components_root: str | Path,
    manifest_path: str | Path,
) -> dict:
    """Prepare one inert governed-batch Nmap task after a read-only policy check.

    The selection MUST be a discovered IPv4 interface address explicitly
    chosen by the operator, not a subnet/gateway/remote host inferred from a
    route. Revalidation and atomic budget reservation happen only at execution.
    """
    if not isinstance(snapshot, HostPreflightSnapshot) or snapshot.schema != 1:
        raise ValueError("Host snapshot is unavailable or incompatible")
    # A preview must not rely on an old or future-dated passive inventory.
    # This is a freshness check, NOT a source of engagement authorisation.
    try:
        observed_at = datetime.fromisoformat(snapshot.collected_at)
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise ValueError("Snapshot timestamp must be timezone-aware")
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("Host snapshot has an invalid collection timestamp") from exc
    now = datetime.now(timezone.utc)
    if not (now - timedelta(minutes=5) <= observed_at <= now + timedelta(seconds=30)):
        raise ValueError("Host snapshot is stale or future-dated; refresh preflight")
    if not isinstance(target, str):
        raise ValueError("Operator must select an exact host IPv4 address")
    try:
        selected = str(ipaddress.IPv4Address(target))
    except ValueError as exc:
        raise ValueError("Operator must select an exact host IPv4 address") from exc
    if not all(isinstance(x, str) and _ID.fullmatch(x) for x in (engagement_id, action_id)):
        raise ValueError("Invalid engagement or action identifier")
    known = {
        item.get("address")
        for item in snapshot.addresses
        if isinstance(item, dict) and item.get("family") == "ipv4"
    }
    if selected not in known:
        raise PermissionError("Selected host IPv4 address was not found in current local inventory")
    readiness = assess_tool_readiness(snapshot, "nmap")
    candidate = readiness.get("tool_candidate") or {}
    if candidate.get("state") != "unverified-present" or not candidate.get("path"):
        raise FileNotFoundError("Local Nmap candidate was not discovered")

    # Component manifest is separately approved and integrity pinned. PATH
    # discovery does not on its own establish trust.
    component = resolve_managed_component(
        components_root=components_root, manifest_path=manifest_path,
        component_name="nmap",
    )
    if Path(candidate["path"]).resolve(strict=True) != component.executable:
        raise PermissionError("Discovered Nmap is not the approved managed component")

    database = Path(authority_db)
    if not database.is_file():
        raise FileNotFoundError("Registered engagement authority database required")
    with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True, timeout=2)) as db:
        row = db.execute(
            "SELECT policy_json, engagement_status, actions_used "
            "FROM engagement_authority WHERE engagement_id=?",
            (engagement_id,),
        ).fetchone()
    if row is None:
        raise PermissionError("Engagement not registered")
    data = json.loads(row[0])
    data["actions_used"] = row[2]
    policy = EngagementExecutionPolicy.from_dict(data)
    decision = evaluate_action(
        policy, engagement_status=row[1], capability="external.nmap.discovery",
        target=selected, impact="low", approval_present=False,
        now=datetime.now(timezone.utc),
    )
    if not decision.allowed:
        raise PermissionError("Engagement policy denied preparation: " + decision.reason_code)

    return {
        "type": "inert-governed-plan-preview",
        "host_snapshot_at": snapshot.collected_at,
        "target_source": "operator-selected-local-ipv4",
        "approved_executable_source": "administrator-managed-component-manifest",
        "engagement_id": engagement_id,
        "execution_status": "not-started",
        "action_reserved": False,
        "fresh_authority_recheck_required": True,
        "execution_opt_in_required": True,
        "plan": {"schema": 1, "tasks": [{
            "kind": "nmap",
            "engagement_id": engagement_id,
            "action_id": action_id,
            "target": selected,
            "executable": str(component.executable),
            "trusted_sha256": component.sha256,
        }]},
        "limitations": [
            "Preview is not a scan or reservation and may be stale before execution.",
            "Discovered interface addresses do not expand engagement scope.",
            "The existing governed-batch command still requires explicit --execute.",
        ],
    }
