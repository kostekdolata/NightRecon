"""Shared workspace coordination over backend-neutral engagement evidence stores.

The local implementation is intentionally simple and network-free. It derives
workspace views from the canonical engagement store instead of maintaining a
second index. File-backed workspaces support serialized local writers; a future
multi-process service/database backend must provide its own concurrency control.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Protocol
import os
import tempfile

from nightrecon_shared_core.contracts import EngagementEnvelope, EngagementMetadata
from nightrecon_shared_core.file_store import FileEngagementStore
from nightrecon_shared_core.engagement_policy import (
    AuthorizationDecision,
    EngagementExecutionPolicy,
    FileEngagementPolicyStore,
    append_authorization_audit,
    evaluate_action,
    read_authorization_audit,
)


@dataclass(frozen=True)
class WorkspaceSummary:
    engagement_id: str
    name: str | None
    status: str | None
    source_nights: tuple[str, ...]
    record_count: int
    evidence_types: tuple[str, ...]


@dataclass(frozen=True)
class EvidenceBreakdown:
    source_night_counts: tuple[tuple[str, int], ...]
    evidence_type_counts: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class WorkspaceTimelineItem:
    evidence_id: str
    source_night: str
    evidence_type: str
    observed_at: str
    provenance: str
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class MergeReport:
    engagement_id: str
    applied: bool
    added_records: int
    identical_records: int
    evidence_conflicts: tuple[str, ...]
    metadata_conflict: bool
    source_nights: tuple[str, ...]


class WorkspaceStore(Protocol):
    def summaries(self) -> tuple[WorkspaceSummary, ...]: ...
    def summary(self, engagement_id: str) -> WorkspaceSummary: ...
    def evidence_breakdown(self, engagement_id: str) -> EvidenceBreakdown: ...
    def envelope(self, engagement_id: str) -> EngagementEnvelope: ...
    def merge_envelope(self, envelope: EngagementEnvelope) -> MergeReport: ...


class LocalWorkspace:
    """Local workspace root shared by independently installed Night apps."""

    STORE_FILENAME = "engagements.json"
    POLICY_FILENAME = "authorization.json"
    AUTHORIZATION_AUDIT_FILENAME = "authorization-audit.jsonl"
    _STATUS_TRANSITIONS = {
        "planned": frozenset({"active", "archived"}),
        "active": frozenset({"paused", "completed"}),
        "paused": frozenset({"active", "completed"}),
        "completed": frozenset({"archived"}),
        "archived": frozenset(),
    }

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        if self.root.exists() and not self.root.is_dir():
            raise ValueError("workspace root must be a directory")
        self.store = FileEngagementStore(self.root / self.STORE_FILENAME)
        self.policy_store = FileEngagementPolicyStore(self.root / self.POLICY_FILENAME)

    def _exists(self, engagement_id: str) -> bool:
        return engagement_id in self.store.engagements()

    def set_execution_policy(
        self, policy: EngagementExecutionPolicy
    ) -> EngagementExecutionPolicy:
        if not self._exists(policy.engagement_id):
            raise ValueError(f"engagement not found: {policy.engagement_id}")
        self.policy_store.set_policy(policy)
        return policy

    def execution_policy(self, engagement_id: str) -> EngagementExecutionPolicy:
        if not self._exists(engagement_id):
            raise ValueError(f"engagement not found: {engagement_id}")
        policy = self.policy_store.policy(engagement_id)
        if policy is None:
            raise ValueError(f"engagement authorization policy not found: {engagement_id}")
        return policy

    def revoke_execution(self, engagement_id: str) -> EngagementExecutionPolicy:
        if not self._exists(engagement_id):
            raise ValueError(f"engagement not found: {engagement_id}")
        return self.policy_store.revoke(engagement_id)

    def authorize_action(
        self,
        engagement_id: str,
        *,
        capability: str,
        target: str,
        impact: str = "standard",
        approval_present: bool = False,
        consume: bool = False,
        now=None,
    ) -> AuthorizationDecision:
        policy = self.execution_policy(engagement_id)
        metadata = self.envelope(engagement_id).metadata
        status = None if metadata is None else metadata.status
        decision = evaluate_action(
            policy,
            engagement_status=status,
            capability=capability,
            target=target,
            impact=impact,
            approval_present=approval_present,
            now=now,
        )
        if decision.allowed and consume:
            updated = self.policy_store.consume_action(engagement_id)
            decision = AuthorizationDecision(
                engagement_id=decision.engagement_id,
                allowed=True,
                reason_code=decision.reason_code,
                reason=decision.reason,
                capability=decision.capability,
                target=decision.target,
                impact=decision.impact,
                approval_present=decision.approval_present,
                actions_used=updated.actions_used,
                max_actions=updated.max_actions,
                remaining_actions=updated.max_actions - updated.actions_used,
            )
        append_authorization_audit(
            self.root / self.AUTHORIZATION_AUDIT_FILENAME,
            decision,
            occurred_at=now,
        )
        return decision

    def authorization_audit(self, engagement_id: str):
        if not self._exists(engagement_id):
            raise ValueError(f"engagement not found: {engagement_id}")
        return tuple(
            item
            for item in read_authorization_audit(
                self.root / self.AUTHORIZATION_AUDIT_FILENAME
            )
            if item.engagement_id == engagement_id
        )

    def create_engagement(self, metadata: EngagementMetadata) -> WorkspaceSummary:
        if self._exists(metadata.engagement_id):
            raise ValueError(f"engagement already exists: {metadata.engagement_id}")
        self.store.set_metadata(metadata)
        return self.summary(metadata.engagement_id)

    def update_status(self, engagement_id: str, status: str) -> WorkspaceSummary:
        envelope = self.envelope(engagement_id)
        metadata = envelope.metadata
        if metadata is None:
            raise ValueError("engagement metadata is required to update status")
        if status == metadata.status:
            return self.summary(engagement_id)
        allowed = self._STATUS_TRANSITIONS.get(metadata.status, frozenset())
        if status not in allowed:
            raise ValueError(
                f"invalid engagement status transition: {metadata.status} -> {status}"
            )
        self.store.replace_metadata(replace(metadata, status=status))
        return self.summary(engagement_id)

    def envelope(self, engagement_id: str) -> EngagementEnvelope:
        if not self._exists(engagement_id):
            raise ValueError(f"engagement not found: {engagement_id}")
        return self.store.export_envelope(engagement_id)

    def timeline(self, engagement_id: str) -> tuple[WorkspaceTimelineItem, ...]:
        records = self.envelope(engagement_id).records
        return tuple(
            WorkspaceTimelineItem(
                evidence_id=record.evidence_id,
                source_night=record.source_night,
                evidence_type=record.evidence_type,
                observed_at=record.observed_at,
                provenance=record.provenance,
                limitations=record.limitations,
            )
            for record in sorted(
                records,
                key=lambda item: (item.observed_at, item.evidence_id),
            )
        )

    def summary(self, engagement_id: str) -> WorkspaceSummary:
        envelope = self.envelope(engagement_id)
        metadata = envelope.metadata
        return WorkspaceSummary(
            engagement_id=engagement_id,
            name=None if metadata is None else metadata.name,
            status=None if metadata is None else metadata.status,
            source_nights=tuple(sorted({r.source_night for r in envelope.records})),
            record_count=len(envelope.records),
            evidence_types=tuple(sorted({r.evidence_type for r in envelope.records})),
        )

    def summaries(self) -> tuple[WorkspaceSummary, ...]:
        return tuple(self.summary(item) for item in self.store.engagements())

    def evidence_breakdown(self, engagement_id: str) -> EvidenceBreakdown:
        self.envelope(engagement_id)
        records = self.store.records(engagement_id)
        by_night = Counter(record.source_night for record in records)
        by_type = Counter(record.evidence_type for record in records)
        return EvidenceBreakdown(
            source_night_counts=tuple(sorted(by_night.items())),
            evidence_type_counts=tuple(sorted(by_type.items())),
        )

    def merge_envelope(self, envelope: EngagementEnvelope) -> MergeReport:
        current = (
            self.store.export_envelope(envelope.engagement_id)
            if self._exists(envelope.engagement_id)
            else EngagementEnvelope(engagement_id=envelope.engagement_id, records=())
        )
        metadata_conflict = (
            current.metadata is not None
            and envelope.metadata is not None
            and current.metadata != envelope.metadata
        )
        existing = {record.evidence_id: record for record in current.records}
        conflicts: list[str] = []
        identical = 0
        added = 0
        for record in envelope.records:
            previous = existing.get(record.evidence_id)
            if previous is None:
                added += 1
            elif previous == record:
                identical += 1
            else:
                conflicts.append(record.evidence_id)

        if metadata_conflict or conflicts:
            source_nights = tuple(sorted({
                record.source_night
                for record in current.records + envelope.records
            }))
            return MergeReport(
                engagement_id=envelope.engagement_id,
                applied=False,
                added_records=0,
                identical_records=identical,
                evidence_conflicts=tuple(sorted(conflicts)),
                metadata_conflict=metadata_conflict,
                source_nights=source_nights,
            )

        self.store.append_envelope(envelope)
        merged = self.store.export_envelope(envelope.engagement_id)
        return MergeReport(
            engagement_id=envelope.engagement_id,
            applied=True,
            added_records=added,
            identical_records=identical,
            evidence_conflicts=(),
            metadata_conflict=False,
            source_nights=tuple(sorted({r.source_night for r in merged.records})),
        )

    def import_file(self, path: str | Path) -> MergeReport:
        envelope = EngagementEnvelope.from_json(
            Path(path).read_text(encoding="utf-8")
        )
        return self.merge_envelope(envelope)

    def export_file(self, engagement_id: str, path: str | Path) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        payload = self.envelope(engagement_id).to_json() + "\n"
        fd, tmp_name = tempfile.mkstemp(
            prefix=destination.name + ".",
            suffix=".tmp",
            dir=str(destination.parent),
            text=True,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, destination)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
