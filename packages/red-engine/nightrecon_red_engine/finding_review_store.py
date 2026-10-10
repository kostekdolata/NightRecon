"""Local deterministic vulnerability review lifecycle.

Stores *review records*, not exploitability assertions. Callers must enforce
engagement permissions before accessing this store.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sqlite3
from contextlib import contextmanager

STATUSES = frozenset({"open", "in-review", "remediation-planned", "resolved", "accepted-risk"})

@dataclass(frozen=True)
class FindingRecord:
    engagement: str
    asset: str
    rule_id: str
    status: str
    evidence_ref: str
    notes: str

class FindingStore:
    def __init__(self, database: str | Path):
        self.database = str(database)
        with self._connect() as con:
            con.execute("""CREATE TABLE IF NOT EXISTS review_findings (
                engagement TEXT NOT NULL, asset TEXT NOT NULL, rule_id TEXT NOT NULL,
                status TEXT NOT NULL, evidence_ref TEXT NOT NULL, notes TEXT NOT NULL,
                PRIMARY KEY (engagement, asset, rule_id)
            )""")
            con.execute("""CREATE TABLE IF NOT EXISTS review_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, engagement TEXT NOT NULL,
                asset TEXT NOT NULL, rule_id TEXT NOT NULL, action TEXT NOT NULL,
                evidence_ref TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""")
    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.database, timeout=5)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def upsert(self, record: FindingRecord) -> None:
        if record.status not in STATUSES:
            raise ValueError("Invalid finding status")
        if not all((record.engagement, record.asset, record.rule_id, record.evidence_ref)):
            raise ValueError("Finding identity and evidence reference are required")
        with self._connect() as con:
            con.execute("""INSERT INTO review_findings
               (engagement,asset,rule_id,status,evidence_ref,notes)
               VALUES (?,?,?,?,?,?)
               ON CONFLICT(engagement,asset,rule_id) DO UPDATE SET
               status=excluded.status,evidence_ref=excluded.evidence_ref,notes=excluded.notes""",
               (record.engagement,record.asset,record.rule_id,record.status,record.evidence_ref,record.notes))
            con.execute("""INSERT INTO review_events
               (engagement,asset,rule_id,action,evidence_ref) VALUES (?,?,?,?,?)""",
               (record.engagement,record.asset,record.rule_id,"review-upsert",record.evidence_ref))

    def list_findings(self, engagement: str) -> tuple[FindingRecord, ...]:
        with self._connect() as con:
            rows = con.execute("""SELECT engagement,asset,rule_id,status,evidence_ref,notes
              FROM review_findings WHERE engagement=? ORDER BY asset,rule_id""", (engagement,)).fetchall()
        return tuple(FindingRecord(*row) for row in rows)

    def retest(self, engagement: str, asset: str, rule_id: str, evidence_ref: str, still_observed: bool) -> None:
        if not evidence_ref:
            raise ValueError("Retest evidence reference required")
        with self._connect() as con:
            existing=con.execute("""SELECT status FROM review_findings WHERE engagement=? AND asset=? AND rule_id=?""",
              (engagement,asset,rule_id)).fetchone()
            if existing is None:
                raise KeyError("Finding not found")
            status="open" if still_observed else "resolved"
            con.execute("""UPDATE review_findings SET status=?, evidence_ref=? WHERE
              engagement=? AND asset=? AND rule_id=?""",(status,evidence_ref,engagement,asset,rule_id))
            con.execute("""INSERT INTO review_events (engagement,asset,rule_id,action,evidence_ref)
              VALUES (?,?,?,?,?)""",(engagement,asset,rule_id,"retest-observed" if still_observed else "retest-not-observed",evidence_ref))
