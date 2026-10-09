"""Read-only operational status for the professional desktop console.

Never provisions engagements, consumes budgets, or starts processes.
"""
from __future__ import annotations
from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3


@dataclass(frozen=True)
class OperationsSnapshot:
    engagement_id: str
    status: str
    remaining_actions: int | None
    events: tuple[str, ...]
    findings: tuple[str, ...]
    warnings: tuple[str, ...]

    def describe(self) -> str:
        lines = [
            "RED NIGHT / OPERATIONS CONSOLE", "",
            f"Engagement: {self.engagement_id or '(none)'}",
            f"Authority: {self.status}",
            f"Remaining authorised actions: {self.remaining_actions if self.remaining_actions is not None else 'unknown'}",
            "", "RECENT EXECUTION EVENTS",
            *(self.events or ("No recorded execution events",)),
            "", "FINDINGS & EVIDENCE",
            *(self.findings or ("No reviewed findings available",)),
            "", "LIMITATIONS",
            *self.warnings,
        ]
        return "\n".join(lines)


def read_operations_snapshot(*, engagement_id: str, authority_db: str | Path,
                             audit_path: str | Path, review_db: str | Path) -> OperationsSnapshot:
    if not engagement_id or len(engagement_id) > 128:
        raise ValueError("Engagement identifier is required")
    status = "UNAVAILABLE"
    remaining = None
    warnings = []
    dbpath = Path(authority_db)
    if dbpath.is_file():
        # SQLite immutable read-only prevents unintentional writes and new DB creation.
        try:
            with sqlite3.connect(dbpath.resolve().as_uri() + "?mode=ro", uri=True, timeout=2) as db:
                row = db.execute(
                    "SELECT policy_json,engagement_status,actions_used FROM engagement_authority WHERE engagement_id=?",
                    (engagement_id,)).fetchone()
                if row:
                    data = json.loads(row[0])
                    status = row[1].upper()
                    if data.get("revoked"):
                        status = "REVOKED"
                    remaining = max(0, int(data.get("max_actions", 0)) - int(row[2]))
                else:
                    warnings.append("Engagement not registered in authority")
        except (sqlite3.Error, OSError, ValueError, TypeError, KeyError):
            warnings.append("Authority unavailable or incompatible")
    else:
        warnings.append("No authority database at selected path")
    events = []
    audit = Path(audit_path)
    if audit.is_file():
        try:
            if audit.stat().st_size > 4 * 1024 * 1024:
                warnings.append("Audit file too large for bounded preview")
            else:
                for line in audit.read_text(encoding="utf-8").splitlines()[-30:]:
                    try:
                        item = json.loads(line)
                        if item.get("engagement_id") == engagement_id:
                            events.append(f"{item.get('recorded_at', '?')}  {item.get('command', '?')}  {item.get('status', '?')}")
                    except (ValueError, TypeError, AttributeError):
                        warnings.append("Malformed audit line skipped")
        except OSError:
            warnings.append("Audit unavailable")
    findings = []
    reviews = Path(review_db)
    if reviews.is_file():
        try:
            with sqlite3.connect(reviews.resolve().as_uri() + "?mode=ro", uri=True, timeout=2) as db:
                rows = db.execute(
                    "SELECT asset,rule_id,status,evidence_ref FROM review_findings WHERE engagement=? ORDER BY asset,rule_id LIMIT 50",
                    (engagement_id,)).fetchall()
                findings = [f"{asset} | {rule} | {state} | evidence: {evidence}"
                            for asset, rule, state, evidence in rows]
        except sqlite3.Error:
            warnings.append("Finding review database unavailable")
    warnings.append("Read-only preview. No scan execution or approval is possible here.")
    return OperationsSnapshot(engagement_id, status, remaining,
                              tuple(events), tuple(findings), tuple(warnings))
