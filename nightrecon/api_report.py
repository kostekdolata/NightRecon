"""Structured non-secret reporting for NightRecon API intelligence."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from nightrecon.api_models import ApiInventory
from nightrecon.session import ScanSession


@dataclass(frozen=True)
class ApiParameterReport:
    name: str
    location: str
    required: bool
    schema_type: str
    schema_format: str


@dataclass(frozen=True)
class ApiOperationReport:
    method: str
    path: str
    operation_id: str
    summary: str
    parameters: tuple[ApiParameterReport, ...]
    request_content_types: tuple[str, ...]
    response_statuses: tuple[str, ...]
    security_schemes: tuple[str, ...]


@dataclass(frozen=True)
class ApiInventoryReport:
    session_id: str
    created_at: str
    target: str
    target_type: str
    scope: tuple[str, ...]
    status: str
    base_origin: str
    specification: str
    specification_version: str
    title: str
    api_version: str
    servers: tuple[str, ...]
    operations: tuple[ApiOperationReport, ...]
    security_scheme_names: tuple[str, ...]
    external_references_observed: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        session: ScanSession,
        base_origin: str,
        inventory: ApiInventory,
    ) -> "ApiInventoryReport":
        return cls(
            session_id=session.session_id,
            created_at=datetime.now(
                timezone.utc
            ).isoformat(),
            target=session.target,
            target_type=session.target_type,
            scope=session.scope,
            status="completed",
            base_origin=base_origin,
            specification=inventory.specification,
            specification_version=inventory.specification_version,
            title=inventory.title,
            api_version=inventory.api_version,
            servers=tuple(
                server.url
                for server in inventory.servers
            ),
            operations=tuple(
                ApiOperationReport(
                    method=operation.method,
                    path=operation.path,
                    operation_id=operation.operation_id,
                    summary=operation.summary,
                    parameters=tuple(
                        ApiParameterReport(
                            name=parameter.name,
                            location=parameter.location,
                            required=parameter.required,
                            schema_type=parameter.schema_type,
                            schema_format=parameter.schema_format,
                        )
                        for parameter in operation.parameters
                    ),
                    request_content_types=operation.request_content_types,
                    response_statuses=operation.response_statuses,
                    security_schemes=operation.security_schemes,
                )
                for operation in inventory.operations
            ),
            security_scheme_names=inventory.security_scheme_names,
            external_references_observed=(
                inventory.external_references_observed
            ),
        )

    @property
    def safe_operation_count(self) -> int:
        return sum(
            operation.method
            in {
                "GET",
                "HEAD",
                "OPTIONS",
            }
            for operation in self.operations
        )

    @property
    def mutating_operation_count(self) -> int:
        return sum(
            operation.method
            in {
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "TRACE",
            }
            for operation in self.operations
        )

    def to_dict(self) -> dict:
        data = asdict(
            self
        )
        data["summary"] = {
            "operations": len(
                self.operations
            ),
            "safe_operations": (
                self.safe_operation_count
            ),
            "mutating_operations": (
                self.mutating_operation_count
            ),
            "servers": len(
                self.servers
            ),
            "security_schemes": len(
                self.security_scheme_names
            ),
            "external_references": len(
                self.external_references_observed
            ),
        }
        return data
