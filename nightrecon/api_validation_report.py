"""Structured reporting for bounded NightRecon API validation."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from nightrecon.api_execution import ApiExecutionResult
from nightrecon.api_planner import ApiOperationSelection
from nightrecon.session import ScanSession


@dataclass(frozen=True)
class ApiValidationRecord:
    selector: str
    method: str
    url: str
    operation_id: str
    success: bool
    reason: str
    status: int | None
    content_type: str
    byte_count: int
    requests_used_after: int

    @classmethod
    def from_result(
        cls,
        *,
        selection: ApiOperationSelection,
        result: ApiExecutionResult,
    ) -> "ApiValidationRecord":
        return cls(
            selector=selection.selector,
            method=result.method,
            url=result.url,
            operation_id=result.operation_id,
            success=result.success,
            reason=result.reason,
            status=result.status,
            content_type=result.content_type,
            byte_count=result.byte_count,
            requests_used_after=result.state.requests_used,
        )


@dataclass(frozen=True)
class ApiValidationReport:
    session_id: str
    created_at: str
    target: str
    target_type: str
    scope: tuple[str, ...]
    status: str
    base_origin: str
    max_requests: int
    max_response_bytes: int
    records: tuple[ApiValidationRecord, ...]

    @classmethod
    def create(
        cls,
        *,
        session: ScanSession,
        base_origin: str,
        max_requests: int,
        max_response_bytes: int,
        records: tuple[ApiValidationRecord, ...],
    ) -> "ApiValidationReport":
        return cls(
            session_id=session.session_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            target=session.target,
            target_type=session.target_type,
            scope=session.scope,
            status="completed",
            base_origin=base_origin,
            max_requests=max_requests,
            max_response_bytes=max_response_bytes,
            records=records,
        )

    @property
    def successful_requests(self) -> int:
        return sum(
            record.success
            for record in self.records
        )

    @property
    def attempted_requests(self) -> int:
        return (
            max(
                (
                    record.requests_used_after
                    for record in self.records
                ),
                default=0,
            )
        )

    def to_dict(self) -> dict:
        data = asdict(
            self
        )
        data["summary"] = {
            "selected_operations": len(
                self.records
            ),
            "attempted_requests": (
                self.attempted_requests
            ),
            "successful_requests": (
                self.successful_requests
            ),
            "failed_requests": (
                len(self.records)
                - self.successful_requests
            ),
        }
        return data
