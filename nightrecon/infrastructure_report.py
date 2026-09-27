"""Secret-free reporting for credentialed infrastructure assessment."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from nightrecon.infrastructure_execution import (
    InfrastructureExecutionResult,
)
from nightrecon.session import ScanSession


@dataclass(frozen=True)
class InfrastructureActionRecord:
    target: str
    transport: str
    action_id: str
    credential_id: str
    success: bool
    reason: str
    facts: tuple[dict[str, str], ...]
    actions_used_after: int

    @classmethod
    def from_result(
        cls,
        result: InfrastructureExecutionResult,
    ) -> "InfrastructureActionRecord":
        return cls(
            target=result.target,
            transport=result.transport.value,
            action_id=result.action_id,
            credential_id=result.credential_id,
            success=result.success,
            reason=result.reason,
            facts=tuple(
                {
                    "key": fact.key,
                    "value": fact.value,
                }
                for fact in result.facts
            ),
            actions_used_after=(
                result.state.actions_used
            ),
        )


@dataclass(frozen=True)
class InfrastructureAssessmentReport:
    session_id: str
    created_at: str
    target: str
    target_type: str
    scope: tuple[str, ...]
    status: str
    transport: str
    username: str
    port: int
    host_key_policy: str
    max_actions: int
    records: tuple[
        InfrastructureActionRecord,
        ...
    ]

    @classmethod
    def create(
        cls,
        *,
        session: ScanSession,
        transport: str,
        username: str,
        port: int,
        max_actions: int,
        records: tuple[
            InfrastructureActionRecord,
            ...
        ],
    ) -> "InfrastructureAssessmentReport":
        return cls(
            session_id=session.session_id,
            created_at=datetime.now(
                timezone.utc
            ).isoformat(),
            target=session.target,
            target_type=session.target_type,
            scope=session.scope,
            status="completed",
            transport=transport,
            username=username,
            port=port,
            host_key_policy="reject",
            max_actions=max_actions,
            records=records,
        )

    def to_dict(
        self,
    ) -> dict:
        data = asdict(
            self
        )
        successful = sum(
            record.success
            for record in self.records
        )
        attempted = max(
            (
                record.actions_used_after
                for record in self.records
            ),
            default=0,
        )
        data["summary"] = {
            "selected_actions": len(
                self.records
            ),
            "attempted_actions": attempted,
            "successful_actions": successful,
            "failed_actions": (
                len(self.records)
                - successful
            ),
        }
        return data


@dataclass(frozen=True)
class SmbInfrastructureAssessmentReport:
    """Secret-free read-only SMB assessment report."""

    session_id: str
    created_at: str
    target: str
    target_type: str
    scope: tuple[str, ...]
    status: str
    transport: str
    username: str
    domain: str
    port: int
    max_actions: int
    max_shares: int
    records: tuple[
        InfrastructureActionRecord,
        ...
    ]

    @classmethod
    def create(
        cls,
        *,
        session: ScanSession,
        username: str,
        domain: str,
        port: int,
        max_actions: int,
        max_shares: int,
        records: tuple[
            InfrastructureActionRecord,
            ...
        ],
    ) -> "SmbInfrastructureAssessmentReport":
        return cls(
            session_id=session.session_id,
            created_at=datetime.now(
                timezone.utc
            ).isoformat(),
            target=session.target,
            target_type=session.target_type,
            scope=session.scope,
            status="completed",
            transport="smb",
            username=username,
            domain=domain,
            port=port,
            max_actions=max_actions,
            max_shares=max_shares,
            records=records,
        )

    def to_dict(
        self,
    ) -> dict:
        data = asdict(
            self
        )
        successful = sum(
            record.success
            for record in self.records
        )
        attempted = max(
            (
                record.actions_used_after
                for record in self.records
            ),
            default=0,
        )
        data["summary"] = {
            "selected_actions": len(
                self.records
            ),
            "attempted_actions": attempted,
            "successful_actions": successful,
            "failed_actions": (
                len(self.records)
                - successful
            ),
        }
        return data



@dataclass(frozen=True)
class WinRmInfrastructureAssessmentReport:
    """Secret-free read-only WinRM assessment report."""

    session_id: str
    created_at: str
    target: str
    target_type: str
    scope: tuple[str, ...]
    status: str
    transport: str
    username: str
    port: int
    authentication: str
    tls_required: bool
    certificate_validation: str
    max_actions: int
    max_patches: int
    records: tuple[
        InfrastructureActionRecord,
        ...
    ]

    @classmethod
    def create(
        cls,
        *,
        session: ScanSession,
        username: str,
        port: int,
        max_actions: int,
        max_patches: int,
        records: tuple[
            InfrastructureActionRecord,
            ...
        ],
    ) -> "WinRmInfrastructureAssessmentReport":
        return cls(
            session_id=session.session_id,
            created_at=datetime.now(
                timezone.utc
            ).isoformat(),
            target=session.target,
            target_type=session.target_type,
            scope=session.scope,
            status="completed",
            transport="winrm",
            username=username,
            port=port,
            authentication="ntlm",
            tls_required=True,
            certificate_validation="required",
            max_actions=max_actions,
            max_patches=max_patches,
            records=records,
        )

    def to_dict(
        self,
    ) -> dict:
        data = asdict(
            self
        )
        successful = sum(
            record.success
            for record in self.records
        )
        attempted = max(
            (
                record.actions_used_after
                for record in self.records
            ),
            default=0,
        )
        data["summary"] = {
            "selected_actions": len(
                self.records
            ),
            "attempted_actions": attempted,
            "successful_actions": successful,
            "failed_actions": (
                len(self.records)
                - successful
            ),
        }
        return data


@dataclass(frozen=True)
class DatabaseInfrastructureAssessmentReport:
    """Secret-free read-only database assessment report."""

    session_id: str
    created_at: str
    target: str
    target_type: str
    scope: tuple[str, ...]
    status: str
    transport: str
    engine: str
    username: str
    database_name: str
    port: int
    authentication: str
    tls_required: bool
    certificate_validation: str
    max_actions: int
    max_schemas: int
    records: tuple[
        InfrastructureActionRecord,
        ...
    ]

    @classmethod
    def create(
        cls,
        *,
        session: ScanSession,
        engine: str,
        username: str,
        database_name: str,
        port: int,
        max_actions: int,
        max_schemas: int,
        records: tuple[
            InfrastructureActionRecord,
            ...
        ],
    ) -> "DatabaseInfrastructureAssessmentReport":
        return cls(
            session_id=session.session_id,
            created_at=datetime.now(
                timezone.utc
            ).isoformat(),
            target=session.target,
            target_type=session.target_type,
            scope=session.scope,
            status="completed",
            transport="database",
            engine=engine,
            username=username,
            database_name=database_name,
            port=port,
            authentication="password",
            tls_required=True,
            certificate_validation="required",
            max_actions=max_actions,
            max_schemas=max_schemas,
            records=records,
        )

    def to_dict(
        self,
    ) -> dict:
        data = asdict(
            self
        )
        successful = sum(
            record.success
            for record in self.records
        )
        attempted = max(
            (
                record.actions_used_after
                for record in self.records
            ),
            default=0,
        )
        data["summary"] = {
            "selected_actions": len(
                self.records
            ),
            "attempted_actions": attempted,
            "successful_actions": successful,
            "failed_actions": (
                len(self.records)
                - successful
            ),
        }
        return data
