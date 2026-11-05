"""Inert Nuclei origin preview; never a source of execution authority."""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
import ipaddress
import json
from pathlib import Path
import re
import sqlite3
from urllib.parse import urlsplit

from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy, evaluate_action
from .host_preflight import HostPreflightSnapshot, assess_tool_readiness
from .managed_components import resolve_managed_component

_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$")


def prepare_local_nuclei_plan(
    *, snapshot: HostPreflightSnapshot, target: str, origin: str,
    engagement_id: str, action_id: str, authority_db: str | Path,
    components_root: str | Path, manifest_path: str | Path,
) -> dict:
    """Preview only the fixed single-GET fingerprint on an operator-selected local IPv4 origin."""
    if not isinstance(snapshot, HostPreflightSnapshot) or snapshot.schema != 1:
        raise ValueError("Host snapshot is unavailable or incompatible")
    try:
        collected = datetime.fromisoformat(snapshot.collected_at)
        if collected.tzinfo is None or collected.utcoffset() is None:
            raise ValueError("Timestamp is naive")
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("Host snapshot has an invalid collection timestamp") from exc
    now = datetime.now(timezone.utc)
    if not (now - timedelta(minutes=5) <= collected <= now + timedelta(seconds=30)):
        raise ValueError("Host snapshot is stale or future-dated; refresh preflight")
    if not isinstance(target, str):
        raise ValueError("Select an exact local IPv4 address")
    try:
        address = str(ipaddress.IPv4Address(target))
    except ValueError as exc:
        raise ValueError("Select an exact local IPv4 address") from exc
    if address not in {
        item.get("address") for item in snapshot.addresses
        if isinstance(item, dict) and item.get("family") == "ipv4"
        and item.get("source") == "local-interface-api"
    }:
        raise PermissionError("Selected address not in current local-interface inventory")
    if not isinstance(origin, str):
        raise ValueError("Select an exact HTTP(S) IPv4 origin")
    try:
        url = urlsplit(origin)
        port = url.port
        host = str(ipaddress.IPv4Address(url.hostname or ""))
    except ValueError as exc:
        raise ValueError("Select an exact HTTP(S) IPv4 origin with a valid port") from exc
    if (url.scheme not in ("http", "https") or host != address
        or url.username is not None or url.password is not None
        or url.path not in ("", "/") or url.query or url.fragment
        or port == 0 or url.netloc != (address + (f":{port}" if port is not None else ""))):
        raise ValueError("HTTP origin must match the selected literal IPv4 host without credentials or paths")
    canonical_origin = f"{url.scheme}://{address}" + (f":{port}" if port is not None else "")
    if not all(isinstance(x, str) and _ID.fullmatch(x) for x in (engagement_id, action_id)):
        raise ValueError("Invalid engagement or action identifier")

    readiness = assess_tool_readiness(snapshot, "nuclei")
    candidate = readiness.get("tool_candidate") or {}
    if candidate.get("state") != "unverified-present" or not candidate.get("path"):
        raise FileNotFoundError("Local Nuclei candidate was not discovered")
    component = resolve_managed_component(
        components_root=components_root, manifest_path=manifest_path, component_name="nuclei",
    )
    if Path(candidate["path"]).resolve(strict=True) != component.executable:
        raise PermissionError("Discovered Nuclei is not the approved managed component")

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
        policy, engagement_status=row[1], capability="external.nuclei.http-fingerprint",
        target=address, impact="low", approval_present=False, now=now,
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
            "kind": "nuclei", "engagement_id": engagement_id, "action_id": action_id,
            "target": canonical_origin, "executable": str(component.executable),
            "trusted_sha256": component.sha256,
        }]},
        "limitations": [
            "This is a read-only preview; no HTTP request, scan, or reservation occurred.",
            "Discovered addresses and tool candidates never confer engagement authorisation.",
            "The existing governed-batch command requires independent fresh checks and explicit --execute.",
        ],
    }
