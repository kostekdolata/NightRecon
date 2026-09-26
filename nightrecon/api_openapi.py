"""Passive OpenAPI/Swagger normalization for NightRecon.

The parser consumes already supplied mappings or local JSON documents.
It does not fetch remote schemas, resolve external references, execute
requests, or retain credentials.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

from nightrecon.api_models import (
    ApiInventory,
    ApiOperation,
    ApiParameter,
    ApiServer,
)


_HTTP_METHODS = (
    "get",
    "head",
    "options",
    "post",
    "put",
    "patch",
    "delete",
    "trace",
)


def _safe_text(value: Any, *, limit: int = 512) -> str:
    if not isinstance(value, str):
        return ""

    return value.strip()[:limit]


def _redacted_url(value: Any) -> str:
    """Drop userinfo, query, and fragment from a declared server URL."""

    text = _safe_text(
        value,
        limit=2048,
    )

    if not text:
        return ""

    parts = urlsplit(text)

    if parts.scheme and parts.netloc:
        hostname = parts.hostname or ""
        port = (
            f":{parts.port}"
            if parts.port is not None
            else ""
        )

        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"

        netloc = f"{hostname}{port}"

        return urlunsplit(
            (
                parts.scheme.lower(),
                netloc,
                parts.path or "",
                "",
                "",
            )
        )

    if text.startswith("/"):
        return text.split(
            "?",
            1,
        )[0].split(
            "#",
            1,
        )[0]

    return ""


def _schema_type(schema: Any) -> tuple[str, str]:
    if not isinstance(schema, Mapping):
        return "", ""

    schema_type = _safe_text(
        schema.get("type"),
        limit=64,
    )
    schema_format = _safe_text(
        schema.get("format"),
        limit=64,
    )

    if not schema_type and "$ref" in schema:
        schema_type = "ref"

    return schema_type, schema_format


def _normalize_parameter(
    value: Any,
) -> ApiParameter | None:
    if not isinstance(value, Mapping):
        return None

    name = _safe_text(
        value.get("name"),
        limit=256,
    )
    location = _safe_text(
        value.get("in"),
        limit=32,
    ).lower()

    if not name or not location:
        return None

    schema = value.get("schema")

    if not isinstance(schema, Mapping):
        schema = value

    schema_type, schema_format = _schema_type(
        schema
    )

    return ApiParameter(
        name=name,
        location=location,
        required=bool(
            value.get("required", False)
        ),
        schema_type=schema_type,
        schema_format=schema_format,
    )


def _parameter_key(
    parameter: ApiParameter,
) -> tuple[str, str]:
    return (
        parameter.location,
        parameter.name,
    )


def _collect_parameters(
    path_item: Mapping[str, Any],
    operation: Mapping[str, Any],
) -> tuple[ApiParameter, ...]:
    merged: dict[
        tuple[str, str],
        ApiParameter,
    ] = {}

    for source in (
        path_item.get("parameters"),
        operation.get("parameters"),
    ):
        if not isinstance(source, list):
            continue

        for raw in source:
            parameter = _normalize_parameter(
                raw
            )

            if parameter is None:
                continue

            merged[
                _parameter_key(parameter)
            ] = parameter

    return tuple(
        merged[key]
        for key in sorted(merged)
    )


def _security_scheme_names(
    document: Mapping[str, Any],
    *,
    specification: str,
) -> tuple[str, ...]:
    if specification == "openapi":
        components = document.get(
            "components",
            {},
        )

        if not isinstance(components, Mapping):
            return ()

        schemes = components.get(
            "securitySchemes",
            {},
        )
    else:
        schemes = document.get(
            "securityDefinitions",
            {},
        )

    if not isinstance(schemes, Mapping):
        return ()

    return tuple(
        sorted(
            _safe_text(
                name,
                limit=256,
            )
            for name in schemes
            if _safe_text(
                name,
                limit=256,
            )
        )
    )


def _operation_security(
    operation: Mapping[str, Any],
    document: Mapping[str, Any],
) -> tuple[str, ...]:
    security = operation.get(
        "security",
        document.get("security", ()),
    )

    if not isinstance(security, list):
        return ()

    names: set[str] = set()

    for requirement in security:
        if not isinstance(
            requirement,
            Mapping,
        ):
            continue

        for name in requirement:
            normalized = _safe_text(
                name,
                limit=256,
            )

            if normalized:
                names.add(
                    normalized
                )

    return tuple(
        sorted(names)
    )


def _request_content_types(
    operation: Mapping[str, Any],
    *,
    specification: str,
) -> tuple[str, ...]:
    if specification == "openapi":
        body = operation.get(
            "requestBody",
            {},
        )

        if not isinstance(body, Mapping):
            return ()

        content = body.get(
            "content",
            {},
        )

        if not isinstance(content, Mapping):
            return ()

        return tuple(
            sorted(
                _safe_text(
                    name,
                    limit=256,
                )
                for name in content
                if _safe_text(
                    name,
                    limit=256,
                )
            )
        )

    consumes = operation.get(
        "consumes",
        (),
    )

    if not isinstance(
        consumes,
        list,
    ):
        return ()

    return tuple(
        sorted(
            {
                _safe_text(
                    item,
                    limit=256,
                )
                for item in consumes
                if _safe_text(
                    item,
                    limit=256,
                )
            }
        )
    )


def _response_statuses(
    operation: Mapping[str, Any],
) -> tuple[str, ...]:
    responses = operation.get(
        "responses",
        {},
    )

    if not isinstance(
        responses,
        Mapping,
    ):
        return ()

    return tuple(
        sorted(
            _safe_text(
                str(code),
                limit=32,
            )
            for code in responses
        )
    )


def _external_refs(
    value: Any,
) -> tuple[str, ...]:
    refs: set[str] = set()

    def walk(item: Any) -> None:
        if isinstance(item, Mapping):
            for key, child in item.items():
                if (
                    key == "$ref"
                    and isinstance(
                        child,
                        str,
                    )
                    and not child.startswith(
                        "#/"
                    )
                ):
                    refs.add(
                        _safe_text(
                            child,
                            limit=2048,
                        )
                    )
                else:
                    walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)

    walk(value)

    return tuple(
        sorted(
            ref
            for ref in refs
            if ref
        )
    )


def normalize_api_description(
    document: Mapping[str, Any],
) -> ApiInventory:
    """Normalize OpenAPI 3.x or Swagger 2.0 without network access."""

    if not isinstance(
        document,
        Mapping,
    ):
        raise ValueError(
            "API description must be a mapping."
        )

    openapi_version = _safe_text(
        document.get("openapi"),
        limit=32,
    )
    swagger_version = _safe_text(
        document.get("swagger"),
        limit=32,
    )

    if openapi_version.startswith("3."):
        specification = "openapi"
        specification_version = (
            openapi_version
        )
    elif swagger_version == "2.0":
        specification = "swagger"
        specification_version = (
            swagger_version
        )
    else:
        raise ValueError(
            "Only OpenAPI 3.x and Swagger 2.0 are supported."
        )

    info = document.get(
        "info",
        {},
    )

    if not isinstance(
        info,
        Mapping,
    ):
        info = {}

    title = _safe_text(
        info.get("title"),
        limit=512,
    )
    api_version = _safe_text(
        info.get("version"),
        limit=128,
    )

    servers: list[ApiServer] = []

    if specification == "openapi":
        raw_servers = document.get(
            "servers",
            (),
        )

        if isinstance(
            raw_servers,
            list,
        ):
            for raw in raw_servers:
                if not isinstance(
                    raw,
                    Mapping,
                ):
                    continue

                url = _redacted_url(
                    raw.get("url")
                )

                if url:
                    servers.append(
                        ApiServer(
                            url=url
                        )
                    )
    else:
        schemes = document.get(
            "schemes",
            (),
        )
        host = _safe_text(
            document.get("host"),
            limit=512,
        )
        base_path = _safe_text(
            document.get("basePath"),
            limit=1024,
        )

        if host:
            if not isinstance(
                schemes,
                list,
            ) or not schemes:
                schemes = ["https"]

            for scheme in schemes:
                normalized_scheme = _safe_text(
                    scheme,
                    limit=16,
                ).lower()

                if normalized_scheme not in {
                    "http",
                    "https",
                }:
                    continue

                url = _redacted_url(
                    f"{normalized_scheme}://{host}{base_path}"
                )

                if url:
                    servers.append(
                        ApiServer(
                            url=url
                        )
                    )

    paths = document.get(
        "paths",
        {},
    )

    if not isinstance(
        paths,
        Mapping,
    ):
        raise ValueError(
            "API description paths must be a mapping."
        )

    operations: list[ApiOperation] = []

    for raw_path in sorted(
        paths,
        key=lambda item: str(item),
    ):
        path = _safe_text(
            raw_path,
            limit=2048,
        )

        if not path.startswith("/"):
            continue

        path_item = paths[
            raw_path
        ]

        if not isinstance(
            path_item,
            Mapping,
        ):
            continue

        for method in _HTTP_METHODS:
            operation = path_item.get(
                method
            )

            if not isinstance(
                operation,
                Mapping,
            ):
                continue

            operations.append(
                ApiOperation(
                    method=method.upper(),
                    path=path,
                    operation_id=_safe_text(
                        operation.get(
                            "operationId"
                        ),
                        limit=512,
                    ),
                    summary=_safe_text(
                        operation.get(
                            "summary"
                        ),
                        limit=512,
                    ),
                    parameters=_collect_parameters(
                        path_item,
                        operation,
                    ),
                    request_content_types=(
                        _request_content_types(
                            operation,
                            specification=specification,
                        )
                    ),
                    response_statuses=(
                        _response_statuses(
                            operation
                        )
                    ),
                    security_schemes=(
                        _operation_security(
                            operation,
                            document,
                        )
                    ),
                )
            )

    return ApiInventory(
        specification=specification,
        specification_version=(
            specification_version
        ),
        title=title,
        api_version=api_version,
        servers=tuple(servers),
        operations=tuple(operations),
        security_scheme_names=(
            _security_scheme_names(
                document,
                specification=specification,
            )
        ),
        external_references_observed=(
            _external_refs(
                document
            )
        ),
    )


def load_api_description_json(
    path: str | Path,
    *,
    max_bytes: int = 2_097_152,
) -> ApiInventory:
    """Load a bounded local JSON API document."""

    if max_bytes < 1:
        raise ValueError(
            "max_bytes must be at least 1."
        )

    file_path = Path(
        path
    )

    payload = file_path.read_bytes()

    if len(payload) > max_bytes:
        raise ValueError(
            "API description exceeds max_bytes."
        )

    try:
        document = json.loads(
            payload.decode(
                "utf-8"
            )
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise ValueError(
            "API description must be valid UTF-8 JSON."
        ) from exc

    if not isinstance(
        document,
        Mapping,
    ):
        raise ValueError(
            "API description root must be an object."
        )

    return normalize_api_description(
        document
    )
