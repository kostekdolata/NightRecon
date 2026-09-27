"""Portable JSON file-backed engagement store for standalone Night applications."""

from __future__ import annotations

from pathlib import Path
import json
import os
import tempfile

from nightrecon_shared_core.contracts import EngagementEnvelope, EvidenceRecord
from nightrecon_shared_core.store import EvidenceConflictError, InMemoryEngagementStore


_STORE_SCHEMA_VERSION = 1


class FileEngagementStore:
    """Small deterministic store suitable for standalone local installations."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._memory = InMemoryEngagementStore()
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("engagement store is not valid UTF-8 JSON") from exc
        if not isinstance(payload, dict) or set(payload) != {"schema_version", "engagements"}:
            raise ValueError("engagement store schema is not supported")
        if payload["schema_version"] != _STORE_SCHEMA_VERSION:
            raise ValueError("engagement store schema version is not supported")
        engagements = payload["engagements"]
        if not isinstance(engagements, list):
            raise ValueError("engagements must be a list")
        seen: set[str] = set()
        for item in engagements:
            envelope = EngagementEnvelope.from_dict(item)
            if envelope.engagement_id in seen:
                raise ValueError("engagement store contains a duplicate engagement")
            seen.add(envelope.engagement_id)
            self._memory.append_envelope(envelope)

    def _persist(self) -> None:
        payload = {
            "schema_version": _STORE_SCHEMA_VERSION,
            "engagements": [
                EngagementEnvelope(
                    engagement_id=engagement_id,
                    records=self._memory.records(engagement_id),
                ).to_dict()
                for engagement_id in self._memory.engagements()
            ],
        }
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=self.path.name + ".",
            suffix=".tmp",
            dir=str(self.path.parent),
            text=True,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(serialized)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self.path)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def append(self, record: EvidenceRecord) -> None:
        before = self._memory.records(record.engagement_id)
        self._memory.append(record)
        after = self._memory.records(record.engagement_id)
        if after != before:
            self._persist()

    def append_envelope(self, envelope: EngagementEnvelope) -> None:
        before = self._memory.records(envelope.engagement_id)
        self._memory.append_envelope(envelope)
        after = self._memory.records(envelope.engagement_id)
        if after != before:
            self._persist()

    def records(
        self,
        engagement_id: str,
        *,
        source_night: str | None = None,
        evidence_type: str | None = None,
    ) -> tuple[EvidenceRecord, ...]:
        return self._memory.records(
            engagement_id,
            source_night=source_night,
            evidence_type=evidence_type,
        )

    def engagements(self) -> tuple[str, ...]:
        return self._memory.engagements()


__all__ = ["EvidenceConflictError", "FileEngagementStore"]
