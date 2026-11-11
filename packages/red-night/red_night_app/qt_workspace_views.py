"""Read-only, redacted operator workspace summaries for Qt navigation.

Never expose raw findings, audit bodies, identifiers, or imported evidence.
Unavailable workspaces explicitly remain non-operational.
"""
from __future__ import annotations

from .qt_operations_bridge import QtOperationsView

WORKSPACES = (
    "Operations", "Target Intelligence", "Engine Console", "Validation Lab",
    "Findings", "Reporting", "Audit & Control",
)


def workspace_summary(index: int, view: QtOperationsView, *, warnings: tuple[str, ...] = ()) -> str:
    if index not in range(len(WORKSPACES)):
        raise ValueError("Unknown workspace")
    if not isinstance(view, QtOperationsView):
        raise TypeError("Expected redacted QtOperationsView")
    notice = "READ-ONLY • Execution, approvals and changes disabled"
    if index == 0:
        body = (
            f"Engagement: {view.engagement_label}\n"
            f"Authority: {view.authority_label}\n"
            f"Remaining authorised actions: {view.actions_label}\n"
            f"Recorded events: {view.events_label}\n"
            f"Recorded findings: {view.findings_label}"
        )
    elif index == 4:
        body = (
            f"Reviewed finding records: {view.findings_label}\n"
            "This is a count from the selected read-only evidence snapshot.\n"
            "Individual findings and evidence review are not available in Qt yet."
        )
    elif index == 6:
        body = (
            f"Authority: {view.authority_label}\n"
            f"Remaining authorised actions: {view.actions_label}\n"
            f"Recorded events: {view.events_label}\n"
            "This screen cannot grant authority or modify the audit trail."
        )
    else:
        body = (
            f"{WORKSPACES[index]} is not connected to a governed Qt workspace.\n"
            "No live telemetry, execution or findings are available here."
        )
    # Warnings may contain source-specific details; show only their count.
    limitations = f"\nSnapshot limitations: {len(warnings)} (details not displayed)" if warnings else ""
    return f"{WORKSPACES[index]}\n\n{body}{limitations}\n\n{notice}"
