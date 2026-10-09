"""SQLite-backed atomic authorization reservation for governed workers.

Separate from legacy JSON policy storage. Caller must keep this ledger's
limits and revocation state synchronised with the authoritative engagement
policy; the ledger fails closed for unknown or revoked engagements.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import sqlite3

@dataclass(frozen=True)
class Reservation:
    engagement_id: str
    action_id: str
    used: int
    limit: int

class AtomicActionLedger:
    def __init__(self, path: str | Path):
        self.path = str(path)
        with sqlite3.connect(self.path, timeout=10) as db:
            db.execute("""CREATE TABLE IF NOT EXISTS action_limits (
                engagement_id TEXT PRIMARY KEY,
                action_limit INTEGER NOT NULL CHECK(action_limit > 0),
                used INTEGER NOT NULL DEFAULT 0 CHECK(used >= 0),
                revoked INTEGER NOT NULL DEFAULT 0
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS reservations (
                engagement_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                PRIMARY KEY (engagement_id,action_id)
            )""")

    def provision(self, engagement_id: str, *, limit: int, revoked: bool = False) -> None:
        if not engagement_id or isinstance(limit,bool) or not isinstance(limit,int) or limit < 1:
            raise ValueError("Invalid action ledger configuration")
        with sqlite3.connect(self.path, timeout=10) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("""INSERT INTO action_limits(engagement_id,action_limit,revoked)
                VALUES(?,?,?) ON CONFLICT(engagement_id) DO UPDATE SET
                action_limit=MIN(action_limits.action_limit,excluded.action_limit),
                revoked=MAX(action_limits.revoked,excluded.revoked)""",
                (engagement_id,limit,int(revoked)))

    def revoke(self, engagement_id: str) -> None:
        with sqlite3.connect(self.path, timeout=10) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE action_limits SET revoked=1 WHERE engagement_id=?",(engagement_id,))

    def reserve(
        self, engagement_id: str, action_id: str, *,
        policy_limit: int | None = None,
        policy_used: int = 0,
        policy_revoked: bool = False,
    ) -> Reservation:
        if not engagement_id or not action_id or len(action_id) > 128:
            raise ValueError("Invalid reservation identity")
        if policy_limit is not None and (type(policy_limit) is not int or policy_limit < 1):
            raise ValueError("Invalid policy limit")
        if type(policy_used) is not int or policy_used < 0:
            raise ValueError("Invalid policy usage")
        if policy_revoked:
            raise PermissionError("Engagement policy revoked")
        with sqlite3.connect(self.path, timeout=10) as db:
            db.execute("BEGIN IMMEDIATE")
            if policy_limit is not None:
                db.execute("""UPDATE action_limits SET
                    action_limit=MIN(action_limit, ?),
                    used=MAX(used, ?)
                    WHERE engagement_id=?""", (policy_limit, policy_used, engagement_id))
            row = db.execute("""SELECT action_limit,used,revoked FROM action_limits
                WHERE engagement_id=?""", (engagement_id,)).fetchone()
            if row is None or row[2]:
                raise PermissionError("Engagement action ledger unavailable or revoked")
            limit, used, _ = row
            if db.execute("""SELECT 1 FROM reservations
                    WHERE engagement_id=? AND action_id=?""",
                    (engagement_id, action_id)).fetchone():
                raise PermissionError("Action identifier already reserved")
            if used >= limit:
                raise PermissionError("Engagement action budget exhausted")
            db.execute("UPDATE action_limits SET used=used+1 WHERE engagement_id=?",
                       (engagement_id,))
            db.execute("INSERT INTO reservations(engagement_id,action_id) VALUES(?,?)",
                       (engagement_id, action_id))
            return Reservation(engagement_id, action_id, used + 1, limit)
