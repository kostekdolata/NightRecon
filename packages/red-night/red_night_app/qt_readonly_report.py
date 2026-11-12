"""Deterministic, non-authoritative reporting preview from a redacted Qt view.

No raw evidence, identifiers, file access, export or authorization side effects.
This is a preview contract, not a professional finding-level report.
"""
from __future__ import annotations

import hashlib
import json

from .qt_operations_bridge import QtOperationsView

_ALLOWED_AUTHORITY = {"ACTIVE", "REVOKED", "EXPIRED", "CLOSED", "SUSPENDED", "UNAVAILABLE"}


def build_readonly_report(view: QtOperationsView, *, warning_count: int = 0) -> dict:
    """Produce a reproducible summary without accepting raw snapshot content."""
    if not isinstance(view, QtOperationsView):
        raise TypeError("Expected redacted QtOperationsView")
    if type(warning_count) is not int or not 0 <= warning_count <= 100000:
        raise ValueError("Invalid limitation count")
    if view.authority_label not in _ALLOWED_AUTHORITY:
        raise ValueError("Unknown authority state")
    if view.engagement_label not in {"Selected engagement", "No engagement selected"}:
        raise ValueError("Unredacted engagement label")
    def count(value: str) -> int | None:
        if value == "—":
            return None
        if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
            raise ValueError("Invalid recorded count")
        number = int(value)
        if number > 1000000000:
            raise ValueError("Unbounded recorded count")
        return number
    actions = None
    if view.actions_label != "Unknown":
        actions = count(view.actions_label)
    if view.authority_label != "ACTIVE" and actions is not None:
        raise ValueError("Actions cannot be available without active authority")
    report = {
        "schema": "red.qt_readonly_report.v1",
        "authority": "presentation_only_not_execution_authorization",
        "engagement": view.engagement_label,
        "engagement_status": view.authority_label,
        "remaining_authorized_actions": actions,
        "recorded_audit_events": count(view.events_label),
        "recorded_review_findings": count(view.findings_label),
        "snapshot_limitation_count": warning_count,
        "finding_status": "not_assessed",
        "limitations": [
            "Counts are from a selected read-only snapshot, not live telemetry.",
            "No finding-level evidence, remediation, retest or exploitability verdict is provided.",
            "This preview cannot authorize actions and is not a final professional report.",
        ],
    }
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    report["report_sha256"] = hashlib.sha256(encoded).hexdigest()
    return report


def render_readonly_report(view: QtOperationsView, *, warning_count: int = 0) -> str:
    """Human-readable, redacted report preview for the Qt Reporting workspace."""
    report = build_readonly_report(view, warning_count=warning_count)
    def shown(value: int | None) -> str:
        return "Unavailable" if value is None else str(value)
    return "\n".join((
        "READ-ONLY REPORT PREVIEW • Not a final professional report",
        f"Engagement: {report['engagement']}",
        f"Authority: {report['engagement_status']}",
        f"Remaining authorised actions: {shown(report['remaining_authorized_actions'])}",
        f"Recorded audit events: {shown(report['recorded_audit_events'])}",
        f"Reviewed finding records: {shown(report['recorded_review_findings'])}",
        f"Snapshot limitations: {report['snapshot_limitation_count']} (details withheld)",
        "Finding verification: Not assessed",
        "No finding-level evidence, remediation, retest or exploitability verdict is available.",
        "No export, scan, approval or modification is possible in this preview.",
        f"Summary SHA-256 (integrity only, not authenticity): {report['report_sha256']}",
    ))
