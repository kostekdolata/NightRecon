"""Normalized API inventory models for NightRecon."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ApiParameter:
    """Non-secret API parameter metadata."""

    name: str
    location: str
    required: bool
    schema_type: str
    schema_format: str = ""


@dataclass(frozen=True)
class ApiOperation:
    """One normalized API operation from an API description."""

    method: str
    path: str
    operation_id: str
    summary: str
    parameters: tuple[ApiParameter, ...]
    request_content_types: tuple[str, ...]
    response_statuses: tuple[str, ...]
    security_schemes: tuple[str, ...]


@dataclass(frozen=True)
class ApiServer:
    """One API server declaration."""

    url: str


@dataclass(frozen=True)
class ApiInventory:
    """Passive normalized API description inventory."""

    specification: str
    specification_version: str
    title: str
    api_version: str
    servers: tuple[ApiServer, ...]
    operations: tuple[ApiOperation, ...]
    security_scheme_names: tuple[str, ...]
    external_references_observed: tuple[str, ...] = ()

    @property
    def operation_count(self) -> int:
        return len(self.operations)
