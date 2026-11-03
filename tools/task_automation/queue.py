"""Local durable queue with immutable approvals, fenced leases and authenticated events.

The integrity key is service-side configuration, never a repository/agent secret.
SQLite is suitable for one controller host; distributed hosting needs a database
with equivalent transactional claims. This module has no GitHub credentials.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3

from .controller import Rejected, _canonical, _integer, _require, _text
from .objectives import Approval, TrustKey, verify_approval


class ObjectiveQueue:
    def __init__(self, path: Path, *, integrity_key: bytes):
        _require(type(integrity_key) is bytes and len(integrity_key) >= 32,
                 "queue integrity key required")
        self.key = integrity_key
        path = Path(path)
        _require(not path.is_symlink(), "queue path is a symlink")
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            opened, named = os.fstat(fd), path.lstat()
            _require(not path.is_symlink() and (opened.st_dev, opened.st_ino)
                     == (named.st_dev, named.st_ino), "queue path changed during open")
            # The host service must verify Windows directory ACLs separately;
            # POSIX mode bits do not represent Windows access control.
            if os.name == "posix":
                _require(opened.st_mode & 0o077 == 0, "queue permissions must be private")
        finally:
            os.close(fd)
        self.db = sqlite3.connect(str(path), isolation_level=None, timeout=5)
        self.db.execute("PRAGMA trusted_schema=OFF")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS approvals (
                objective_id TEXT PRIMARY KEY, digest TEXT NOT NULL, envelope BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS objectives (
                objective_id TEXT PRIMARY KEY REFERENCES approvals(objective_id),
                record BLOB NOT NULL, mac TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                objective_id TEXT NOT NULL REFERENCES approvals(objective_id),
                version INTEGER NOT NULL, event TEXT NOT NULL,
                record BLOB NOT NULL, previous_mac TEXT NOT NULL, mac TEXT NOT NULL,
                PRIMARY KEY (objective_id, version)
            );
            CREATE TABLE IF NOT EXISTS artifacts (
                digest TEXT PRIMARY KEY, payload BLOB NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS approvals_no_update BEFORE UPDATE ON approvals
                BEGIN SELECT RAISE(ABORT, 'immutable approval'); END;
            CREATE TRIGGER IF NOT EXISTS approvals_no_delete BEFORE DELETE ON approvals
                BEGIN SELECT RAISE(ABORT, 'immutable approval'); END;
            CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
                BEGIN SELECT RAISE(ABORT, 'append-only events'); END;
            CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
                BEGIN SELECT RAISE(ABORT, 'append-only events'); END;
        """)

    def close(self):
        self.db.close()

    @contextmanager
    def _transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        else:
            self.db.execute("COMMIT")

    def _mac(self, objective_id: str, version: int, event: str,
             record: bytes, previous: str) -> str:
        message = _canonical({"id": objective_id, "version": version, "event": event,
                              "record_sha256": hashlib.sha256(record).hexdigest(),
                              "previous": previous})
        return hmac.new(self.key, b"nightrecon-queue-v1\x00" + message,
                        hashlib.sha256).hexdigest()

    def _read(self, objective_id: str) -> dict:
        row = self.db.execute("SELECT record,mac FROM objectives WHERE objective_id=?",
                              (objective_id,)).fetchone()
        _require(row is not None, "unknown objective")
        events = self.db.execute(
            "SELECT version,event,record,previous_mac,mac FROM events WHERE objective_id=? ORDER BY version LIMIT 2001",
            (objective_id,)).fetchall()
        previous = "0" * 64
        _require(events and len(events) <= 2000, "missing or oversized queue history")
        for index, (version, event, record, predecessor, mac) in enumerate(events):
            expected = self._mac(objective_id, version, event, record, previous)
            _require(version == index and predecessor == previous
                     and hmac.compare_digest(expected, mac), "queue event authentication failed")
            previous = mac
        _require(row == (events[-1][2], events[-1][4]), "queue state/history mismatch")
        record = json.loads(row[0])
        _require(record["version"] == len(events) - 1, "queue version mismatch")
        return record

    def _write(self, record: dict, event: str):
        objective_id = record["objective_id"]
        previous = self.db.execute("SELECT mac FROM objectives WHERE objective_id=?",
                                   (objective_id,)).fetchone()
        previous_mac = previous[0] if previous else "0" * 64
        raw = _canonical(record)
        mac = self._mac(objective_id, record["version"], event, raw, previous_mac)
        self.db.execute("INSERT INTO events VALUES (?,?,?,?,?,?)",
                        (objective_id, record["version"], event, raw, previous_mac, mac))
        self.db.execute("INSERT INTO objectives VALUES (?,?,?) ON CONFLICT(objective_id) "
                        "DO UPDATE SET record=excluded.record,mac=excluded.mac",
                        (objective_id, raw, mac))

    def enqueue(self, raw: bytes, policy, owner_keys: dict[str, TrustKey], *, now: int) -> dict:
        approval = verify_approval(raw, policy, owner_keys, now=now)
        with self._transaction():
            existing = self.db.execute("SELECT digest,envelope FROM approvals WHERE objective_id=?",
                                       (approval.objective_id,)).fetchone()
            if existing:
                _require(existing[0] == approval.digest, "objective approval conflict")
                existing_approval = verify_approval(existing[1], policy, owner_keys, now=now)
                _require(existing_approval.digest == approval.digest, "stored approval changed")
                return self._read(approval.objective_id)
            self.db.execute("INSERT INTO approvals VALUES (?,?,?)",
                            (approval.objective_id, approval.digest, raw))
            record = {
                "objective_id": approval.objective_id, "approval_digest": approval.digest,
                "owner": approval.owner, "permitted_paths": list(approval.task.permitted_paths),
                "acceptance_criteria": list(approval.task.acceptance_criteria),
                "resource_limits": approval.limits.__dict__,
                "release_permissions": {"authorized": approval.release_authorized,
                    "tag": approval.release_tag, "artifact_names": list(approval.artifact_names),
                    "signing_key_ids": list(approval.signing_key_ids)},
                "branch": approval.task.branch, "base_sha": approval.task.base_sha,
                "parent_sha": approval.task.base_sha, "state": "pending", "version": 0,
                "batch": 0, "repairs": 0, "attempts": 0, "reserved_tokens": 0,
                "reserved_cost_microusd": 0, "started_at": now,
                "deadline": min(approval.expires_at, now + approval.limits.max_wall_seconds),
                "lease_owner": None, "lease_generation": 0, "lease_until": 0,
                "intent": None, "commits": [], "reason": None,
                "plan": None, "merge_sha": None, "release_result": None,
            }
            self._write(record, "approved")
            return record

    def read(self, objective_id: str) -> dict:
        with self._transaction():
            return self._read(objective_id)

    def approval(self, objective_id: str, policy, owner_keys, *, now: int) -> Approval:
        with self._transaction():
            record = self._read(objective_id)
            row = self.db.execute("SELECT envelope FROM approvals WHERE objective_id=?",
                                   (objective_id,)).fetchone()
            approval = verify_approval(row[0], policy, owner_keys, now=now)
            _require(record["approval_digest"] == approval.digest, "approval/history mismatch")
            return approval

    def claim(self, objective_id: str, *, worker: str, now: int, lease_seconds: int = 60) -> dict:
        _text(worker, 128)
        _integer(now, 0, 2**53 - 1)
        _integer(lease_seconds, 1, 300)
        with self._transaction():
            record = self._read(objective_id)
            _require(record["state"] not in {"completed", "failed", "blocked"}, "terminal objective")
            _require(now < record["deadline"], "objective deadline exceeded")
            _require(record["lease_until"] <= now, "objective lease already held")
            # A pending irreversible operation needs explicit remote reconciliation.
            if record["intent"] is not None:
                record.update(state="blocked", reason="unresolved publication intent; reconcile remote state")
            else:
                record.update(lease_owner=worker,
                              lease_generation=record["lease_generation"] + 1,
                              lease_until=min(now + lease_seconds, record["deadline"]))
                if record["state"] == "pending":
                    record["state"] = "admitted"
            record["version"] += 1
            self._write(record, "claimed" if record["state"] != "blocked" else "reconciliation_required")
            return record

    def update(self, objective_id: str, *, worker: str, generation: int,
               version: int, now: int, event: str, changes: dict) -> dict:
        """Trusted service mutation, guarded by optimistic version and lease fencing."""
        _text(event, 128)
        allowed = {"state", "parent_sha", "batch", "repairs", "attempts", "reserved_tokens",
                   "reserved_cost_microusd", "intent", "commits", "reason", "lease_until",
                   "plan", "merge_sha", "release_result"}
        _require(type(changes) is dict and set(changes) <= allowed, "immutable/unknown queue field")
        with self._transaction():
            record = self._read(objective_id)
            _require(record["state"] not in {"completed", "failed", "blocked"}, "terminal objective")
            _require(record["lease_owner"] == worker and record["lease_generation"] == generation
                     and record["version"] == version and now < record["lease_until"]
                     and now < record["deadline"], "stale lease/version or deadline")
            new = record | changes
            for counter in ("attempts", "reserved_tokens", "reserved_cost_microusd"):
                _require(type(new[counter]) is int and new[counter] >= record[counter],
                         "resource counters cannot decrease")
            limits = record["resource_limits"]
            _require(new["attempts"] <= limits["max_attempts"]
                     and new["reserved_tokens"] <= limits["max_tokens"]
                     and new["reserved_cost_microusd"] <= limits["max_cost_microusd"],
                     "resource reservation exceeds signed limits")
            _require(type(new["batch"]) is int and record["batch"] <= new["batch"] <= limits["max_batches"]
                     and type(new["repairs"]) is int and 0 <= new["repairs"] <= limits["max_repairs_per_batch"],
                     "batch or repair limit exceeded")
            _require(new["state"] in {"admitted", "running", "validating", "repairing",
                                      "blocked", "failed", "completed"}, "invalid objective state")
            edges = {"admitted": {"running", "blocked", "failed"},
                     "running": {"running", "validating", "blocked", "failed"},
                     "validating": {"validating", "running", "repairing", "blocked", "failed", "completed"},
                     "repairing": {"repairing", "validating", "blocked", "failed"}}
            _require(new["state"] in edges[record["state"]], "illegal objective transition")
            if new["state"] in {"blocked", "failed"}:
                _text(new["reason"], 1024)
            _require(new["lease_until"] <= record["deadline"], "lease exceeds deadline")
            new["version"] += 1
            self._write(new, event)
            return new

    def reserve_attempt(self, approval: Approval, *, worker: str, generation: int,
                        version: int, now: int, tokens: int, cost_microusd: int) -> dict:
        _integer(tokens, 1, approval.limits.max_tokens)
        _integer(cost_microusd, 1, approval.limits.max_cost_microusd)
        # Reserve the worst case before a remote call. Never silently refund it.
        record = self.read(approval.objective_id)
        attempts = record["attempts"] + 1
        reserved_tokens = record["reserved_tokens"] + tokens
        reserved_cost = record["reserved_cost_microusd"] + cost_microusd
        _require(record["approval_digest"] == approval.digest
                 and attempts <= approval.limits.max_attempts
                 and reserved_tokens <= approval.limits.max_tokens
                 and reserved_cost <= approval.limits.max_cost_microusd,
                 "objective resource budget exhausted")
        return self.update(approval.objective_id, worker=worker, generation=generation,
                           version=version, now=now, event="attempt_budget_reserved",
                           changes={"attempts": attempts, "reserved_tokens": reserved_tokens,
                                    "reserved_cost_microusd": reserved_cost})

    def events(self, objective_id: str) -> list[dict]:
        with self._transaction():
            self._read(objective_id)
            return [{"version": version, "event": event, "record": json.loads(raw)}
                    for version, event, raw in self.db.execute(
                        "SELECT version,event,record FROM events WHERE objective_id=? ORDER BY version",
                        (objective_id,))]

    def expire(self, objective_id: str, *, now: int) -> dict:
        """A trusted recovery poll can persist a terminal timeout without a lease."""
        with self._transaction():
            record = self._read(objective_id)
            expired = now >= record["deadline"]
            uncertain = record["intent"] is not None and 0 < record["lease_until"] <= now
            if record["state"] not in {"completed", "blocked", "failed"} and (expired or uncertain):
                record.update(state="blocked", reason="objective deadline/lease exceeded; reconcile any pending intent")
                record["version"] += 1
                self._write(record, "objective_timed_out")
            return record

    def store_artifact(self, payload: bytes) -> str:
        _require(type(payload) is bytes and len(payload) <= 67108864, "artifact byte limit")
        digest = hashlib.sha256(payload).hexdigest()
        with self._transaction():
            self.db.execute("INSERT OR IGNORE INTO artifacts VALUES (?,?)", (digest, payload))
            stored = self.db.execute("SELECT payload FROM artifacts WHERE digest=?", (digest,)).fetchone()[0]
            _require(stored == payload, "artifact store collision/tampering")
        return digest

    def artifact(self, digest: str) -> bytes:
        from .controller import _sha
        _sha(digest, 64)
        row = self.db.execute("SELECT payload FROM artifacts WHERE digest=?", (digest,)).fetchone()
        _require(row is not None and hashlib.sha256(row[0]).hexdigest() == digest,
                 "missing or tampered artifact")
        return row[0]
