"""Transactional engagement policy and reservation authority.

One SQLite transaction checks policy state, target scope, capability, approval,
validity window and action budget, then reserves a unique action ID. This
standalone store is not yet the production policy backend or live worker.
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import json
import sqlite3

from nightrecon_shared_core.engagement_policy import (
    EngagementExecutionPolicy, evaluate_action,
)

@dataclass(frozen=True)
class ReservedDecision:
    engagement_id: str
    action_id: str
    used: int
    remaining: int

class TransactionalPolicyAuthority:
    def __init__(self, database: str | Path):
        self.database = str(database)
        with self._db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS engagement_authority(
                engagement_id TEXT PRIMARY KEY,
                policy_json TEXT NOT NULL,
                engagement_status TEXT NOT NULL,
                actions_used INTEGER NOT NULL DEFAULT 0,
                revision INTEGER NOT NULL DEFAULT 1
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS authority_reservations(
                engagement_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                PRIMARY KEY(engagement_id,action_id)
            )""")
    def _db(self):
        return sqlite3.connect(self.database, timeout=10)

    def register(self, policy: EngagementExecutionPolicy, *, status: str) -> None:
        if status not in {"planned","active","paused","completed","archived"}:
            raise ValueError("Invalid engagement status")
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("""INSERT INTO engagement_authority
              (engagement_id,policy_json,engagement_status,actions_used)
              VALUES(?,?,?,?)""",
              (policy.engagement_id,json.dumps(policy.to_dict()),status,policy.actions_used))

    def set_status(self, engagement_id: str, status: str) -> None:
        if status not in {"planned","active","paused","completed","archived"}:
            raise ValueError("Invalid engagement status")
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            changed=db.execute("""UPDATE engagement_authority
              SET engagement_status=?,revision=revision+1 WHERE engagement_id=?""",
              (status,engagement_id))
            if changed.rowcount!=1:
                raise KeyError("Engagement not found")

    def revoke(self, engagement_id: str) -> None:
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT policy_json FROM engagement_authority WHERE engagement_id=?",
                           (engagement_id,)).fetchone()
            if row is None:
                raise KeyError("Engagement not found")
            policy=json.loads(row[0])
            policy["revoked"]=True
            db.execute("""UPDATE engagement_authority SET policy_json=?,
              revision=revision+1 WHERE engagement_id=?""",
              (json.dumps(policy),engagement_id))

    def reserve(self, *, engagement_id: str, action_id: str, capability: str,
                target: str, impact: str = "standard", approval_present: bool = False,
                now: datetime | None = None) -> ReservedDecision:
        if not isinstance(action_id,str) or not action_id or len(action_id)>128:
            raise ValueError("Invalid action identifier")
        current=now or datetime.now(timezone.utc)
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row=db.execute("""SELECT policy_json,engagement_status,actions_used
              FROM engagement_authority WHERE engagement_id=?""",(engagement_id,)).fetchone()
            if row is None:
                raise PermissionError("Engagement not registered")
            policy_data=json.loads(row[0])
            policy_data["actions_used"]=row[2]
            policy=EngagementExecutionPolicy.from_dict(policy_data)
            decision=evaluate_action(
                policy,engagement_status=row[1],capability=capability,
                target=target,impact=impact,approval_present=approval_present,now=current)
            if not decision.allowed:
                raise PermissionError(decision.reason_code)
            if db.execute("""SELECT 1 FROM authority_reservations
                 WHERE engagement_id=? AND action_id=?""",(engagement_id,action_id)).fetchone():
                raise PermissionError("Duplicate action identifier")
            db.execute("""INSERT INTO authority_reservations(engagement_id,action_id)
                VALUES(?,?)""",(engagement_id,action_id))
            db.execute("""UPDATE engagement_authority SET
                actions_used=actions_used+1,revision=revision+1 WHERE engagement_id=?""",
                (engagement_id,))
            return ReservedDecision(engagement_id,action_id,row[2]+1,
                                    policy.max_actions-row[2]-1)
