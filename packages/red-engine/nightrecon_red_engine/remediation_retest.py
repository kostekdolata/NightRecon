"""Persistent remediation lifecycle and controlled retest tracking."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
import json
import os
import tempfile

from nightrecon_red_engine.controlled_validation import (
    ControlledValidationResult,
    ValidationState,
)


class RemediationStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in-progress"
    READY_FOR_RETEST = "ready-for-retest"
    VERIFIED = "verified"
    REGRESSED = "regressed"
    ACCEPTED = "accepted"


_TRANSITIONS = {
    RemediationStatus.OPEN: frozenset({
        RemediationStatus.IN_PROGRESS, RemediationStatus.ACCEPTED,
    }),
    RemediationStatus.IN_PROGRESS: frozenset({
        RemediationStatus.READY_FOR_RETEST, RemediationStatus.ACCEPTED,
    }),
    RemediationStatus.READY_FOR_RETEST: frozenset({
        RemediationStatus.IN_PROGRESS, RemediationStatus.ACCEPTED,
    }),
    RemediationStatus.VERIFIED: frozenset(),
    RemediationStatus.REGRESSED: frozenset({
        RemediationStatus.IN_PROGRESS, RemediationStatus.ACCEPTED,
    }),
    RemediationStatus.ACCEPTED: frozenset(),
}


def _required(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field} must be a nonblank, trimmed string")
    return value


@dataclass(frozen=True)
class RemediationFinding:
    engagement_id: str
    finding_id: str
    title: str
    remediation: str
    status: RemediationStatus
    created_at: str
    updated_at: str
    last_validation_id: str | None = None
    last_retest_state: str | None = None

    def __post_init__(self) -> None:
        _required(self.engagement_id, "engagement_id")
        _required(self.finding_id, "finding_id")
        _required(self.title, "title")
        _required(self.remediation, "remediation")


@dataclass(frozen=True)
class RetestOutcome:
    finding_id: str
    previous_status: str
    resulting_status: str
    validation_id: str
    validation_state: str
    conclusive: bool
    interpretation: str


class RemediationStore:
    SCHEMA_VERSION = 1

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._findings: dict[str, RemediationFinding] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("remediation store is not valid UTF-8 JSON") from exc
        if not isinstance(payload, dict) or set(payload) != {"schema_version", "findings"}:
            raise ValueError("remediation store schema is not supported")
        if payload["schema_version"] != self.SCHEMA_VERSION:
            raise ValueError("remediation store schema version is not supported")
        for item in payload["findings"]:
            decoded = dict(item)
            decoded["status"] = RemediationStatus(decoded["status"])
            finding = RemediationFinding(**decoded)
            if finding.finding_id in self._findings:
                raise ValueError("remediation store contains duplicate finding IDs")
            self._findings[finding.finding_id] = finding

    def _persist(self) -> None:
        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "findings": [
                {
                    **asdict(self._findings[key]),
                    "status": self._findings[key].status.value,
                }
                for key in sorted(self._findings)
            ],
        }
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=self.path.name + ".", suffix=".tmp",
            dir=str(self.path.parent), text=True,
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

    def create(
        self,
        *,
        engagement_id: str,
        finding_id: str,
        title: str,
        remediation: str,
        now: datetime | None = None,
    ) -> RemediationFinding:
        if finding_id in self._findings:
            raise ValueError(f"finding already exists: {finding_id}")
        timestamp = (datetime.now(timezone.utc) if now is None else now)
        if timestamp.tzinfo is None:
            raise ValueError("now must include a timezone")
        finding = RemediationFinding(
            engagement_id=engagement_id,
            finding_id=finding_id,
            title=title,
            remediation=remediation,
            status=RemediationStatus.OPEN,
            created_at=timestamp.isoformat(),
            updated_at=timestamp.isoformat(),
        )
        self._findings[finding_id] = finding
        self._persist()
        return finding

    def get(self, finding_id: str) -> RemediationFinding:
        finding = self._findings.get(finding_id)
        if finding is None:
            raise ValueError(f"finding not found: {finding_id}")
        return finding

    def transition(
        self,
        finding_id: str,
        status: RemediationStatus,
        *,
        now: datetime | None = None,
    ) -> RemediationFinding:
        finding = self.get(finding_id)
        if status == finding.status:
            return finding
        if status not in _TRANSITIONS[finding.status]:
            raise ValueError(
                f"invalid remediation transition: {finding.status.value} -> {status.value}"
            )
        timestamp = datetime.now(timezone.utc) if now is None else now
        if timestamp.tzinfo is None:
            raise ValueError("now must include a timezone")
        updated = replace(finding, status=status, updated_at=timestamp.isoformat())
        self._findings[finding_id] = updated
        self._persist()
        return updated

    def record_retest(
        self,
        finding_id: str,
        result: ControlledValidationResult,
        *,
        now: datetime | None = None,
    ) -> RetestOutcome:
        finding = self.get(finding_id)
        if finding.status is not RemediationStatus.READY_FOR_RETEST:
            raise ValueError("finding must be ready-for-retest before recording a retest")
        if result.engagement_id != finding.engagement_id:
            raise ValueError("retest result belongs to a different engagement")
        timestamp = datetime.now(timezone.utc) if now is None else now
        if timestamp.tzinfo is None:
            raise ValueError("now must include a timezone")

        if result.state is ValidationState.NOT_CONFIRMED:
            next_status = RemediationStatus.VERIFIED
            conclusive = True
            interpretation = "The previously validated condition was not reproduced."
        elif result.state is ValidationState.CONFIRMED:
            next_status = RemediationStatus.REGRESSED
            conclusive = True
            interpretation = "The previously validated condition is still present."
        else:
            next_status = finding.status
            conclusive = False
            interpretation = (
                "Retest was inconclusive; finding remains ready for retest."
            )

        updated = replace(
            finding,
            status=next_status,
            updated_at=timestamp.isoformat(),
            last_validation_id=result.validation_id,
            last_retest_state=result.state.value,
        )
        self._findings[finding_id] = updated
        self._persist()
        return RetestOutcome(
            finding_id=finding_id,
            previous_status=finding.status.value,
            resulting_status=next_status.value,
            validation_id=result.validation_id,
            validation_state=result.state.value,
            conclusive=conclusive,
            interpretation=interpretation,
        )

    def list(self, engagement_id: str | None = None) -> tuple[RemediationFinding, ...]:
        values = self._findings.values()
        if engagement_id is not None:
            values = (
                finding for finding in values
                if finding.engagement_id == engagement_id
            )
        return tuple(sorted(values, key=lambda item: item.finding_id))
