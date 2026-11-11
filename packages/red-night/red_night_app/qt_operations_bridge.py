"""Fail-closed presentation adapter for existing Red Night operations snapshots.

No filesystem, network, Qt, process, or authorization side effects.
The caller must explicitly supply an already-read snapshot; absent data is unknown.
"""
from __future__ import annotations

from dataclasses import dataclass

from .operations_read_model import OperationsSnapshot


@dataclass(frozen=True)
class QtOperationsView:
    engagement_label: str
    authority_label: str
    actions_label: str
    events_label: str
    findings_label: str
    status_message: str


def present_operations(snapshot: OperationsSnapshot | None) -> QtOperationsView:
    if snapshot is None:
        return QtOperationsView(
            "No engagement selected", "UNAVAILABLE", "Unknown", "—", "—",
            "Read-only preview • No engagement connected • Execution disabled",
        )
    if not isinstance(snapshot, OperationsSnapshot):
        raise TypeError("Expected an OperationsSnapshot")
    # Do not expose raw audit events, finding bodies, credentials or identifiers
    # in the overview. These counts are not live scan metrics.
    authority = snapshot.status if snapshot.status in {
        "ACTIVE", "REVOKED", "EXPIRED", "CLOSED", "SUSPENDED",
    } else "UNAVAILABLE"
    actions = str(snapshot.remaining_actions) if (
        authority == "ACTIVE"
        and type(snapshot.remaining_actions) is int
        and snapshot.remaining_actions >= 0
    ) else "Unknown"
    return QtOperationsView(
        "Selected engagement" if snapshot.engagement_id else "No engagement selected",
        authority,
        actions,
        str(len(snapshot.events)),
        str(len(snapshot.findings)),
        "Read-only snapshot • No scan or approval available in Qt",
    )
