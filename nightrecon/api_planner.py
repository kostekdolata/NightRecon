"""Safe schema-derived API operation selection for NightRecon."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon.api_models import (
    ApiInventory,
    ApiOperation,
)
from nightrecon.web_crawl import (
    normalize_http_url,
    url_origin,
)


@dataclass(frozen=True)
class ApiOperationSelection:
    """One explicit schema operation selected for bounded validation."""

    selector: str
    operation: ApiOperation
    url: str


def operation_selector(
    operation: ApiOperation,
) -> str:
    """Return the stable human selector for an API operation."""

    return (
        operation.operation_id
        if operation.operation_id
        else f"{operation.method} {operation.path}"
    )


def _operation_requires_values(
    operation: ApiOperation,
) -> bool:
    return any(
        parameter.required
        for parameter in operation.parameters
    )


def select_api_operations(
    *,
    inventory: ApiInventory,
    selectors: tuple[str, ...],
    base_url: str,
) -> tuple[ApiOperationSelection, ...]:
    """Select explicit safe operations without inventing parameter values."""

    if not selectors:
        raise ValueError(
            "At least one API operation selector is required."
        )

    normalized_base = normalize_http_url(
        base_url
    )
    origin = url_origin(
        normalized_base
    )
    base = normalized_base.rstrip(
        "/"
    )

    indexed: dict[
        str,
        list[ApiOperation],
    ] = {}

    for operation in inventory.operations:
        selector = operation_selector(
            operation
        )
        indexed.setdefault(
            selector,
            [],
        ).append(
            operation
        )

    selections: list[
        ApiOperationSelection
    ] = []
    seen: set[str] = set()

    for raw_selector in selectors:
        selector = raw_selector.strip()

        if not selector:
            raise ValueError(
                "API operation selectors must be non-empty."
            )

        matches = indexed.get(
            selector,
            [],
        )

        if not matches:
            raise ValueError(
                f"Unknown API operation selector: {selector}"
            )

        if len(matches) != 1:
            raise ValueError(
                f"Ambiguous API operation selector: {selector}"
            )

        operation = matches[0]

        if operation.method not in {
            "GET",
            "HEAD",
        }:
            raise ValueError(
                f"API operation '{selector}' uses blocked method "
                f"{operation.method}."
            )

        if _operation_requires_values(
            operation
        ):
            raise ValueError(
                f"API operation '{selector}' requires parameter values "
                "and cannot be executed without explicit value support."
            )

        if (
            "{"
            in operation.path
            or "}"
            in operation.path
        ):
            raise ValueError(
                f"API operation '{selector}' contains unresolved path "
                "parameters."
            )

        url = normalize_http_url(
            f"{base}/{operation.path.lstrip('/')}"
        )

        if url_origin(
            url
        ) != origin:
            raise ValueError(
                f"API operation '{selector}' resolved outside the "
                "authorized origin."
            )

        dedupe_key = (
            f"{operation.method} {url}"
        )

        if dedupe_key in seen:
            continue

        seen.add(
            dedupe_key
        )
        selections.append(
            ApiOperationSelection(
                selector=selector,
                operation=operation,
                url=url,
            )
        )

    return tuple(
        selections
    )
