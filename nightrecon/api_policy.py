"""Fail-closed request policy for NightRecon API intelligence.

This module contains authorization policy only. It sends no requests.
"""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon.web_crawl import (
    normalize_http_url,
    url_origin,
)


@dataclass(frozen=True)
class ApiRequestPolicy:
    """Safety limits for future schema-derived API requests."""

    origin: str
    max_requests: int = 25
    allowed_methods: tuple[str, ...] = (
        "GET",
        "HEAD",
    )

    def __post_init__(self) -> None:
        normalized_origin = url_origin(
            self.origin
        )

        if self.max_requests < 1:
            raise ValueError(
                "max_requests must be at least 1."
            )

        methods = tuple(
            dict.fromkeys(
                method.strip().upper()
                for method in self.allowed_methods
                if isinstance(
                    method,
                    str,
                )
                and method.strip()
            )
        )

        if not methods:
            raise ValueError(
                "allowed_methods must include at least one HTTP method."
            )

        object.__setattr__(
            self,
            "origin",
            normalized_origin,
        )
        object.__setattr__(
            self,
            "allowed_methods",
            methods,
        )


@dataclass(frozen=True)
class ApiRequestState:
    """Immutable API request accounting."""

    requests_used: int
    max_requests: int

    @property
    def requests_remaining(self) -> int:
        return max(
            self.max_requests
            - self.requests_used,
            0,
        )


@dataclass(frozen=True)
class ApiRequest:
    """One proposed schema-derived API request."""

    url: str
    method: str
    operation_id: str = ""


@dataclass(frozen=True)
class ApiRequestDecision:
    """Pre-network API authorization decision."""

    allowed: bool
    reason: str
    normalized_url: str
    method: str
    operation_id: str


def authorize_api_request(
    *,
    request: ApiRequest,
    policy: ApiRequestPolicy,
    state: ApiRequestState,
) -> ApiRequestDecision:
    """Authorize one API request without executing network activity."""

    if state.requests_used < 0:
        raise ValueError(
            "requests_used cannot be negative."
        )

    normalized_url = normalize_http_url(
        request.url
    )
    method = request.method.strip().upper()

    if not method:
        raise ValueError(
            "API request method must be non-empty."
        )

    def deny(
        reason: str,
    ) -> ApiRequestDecision:
        return ApiRequestDecision(
            allowed=False,
            reason=reason,
            normalized_url=normalized_url,
            method=method,
            operation_id=request.operation_id,
        )

    if state.requests_used >= policy.max_requests:
        return deny(
            "request_budget_exhausted"
        )

    if url_origin(
        normalized_url
    ) != policy.origin:
        return deny(
            "outside_authorized_origin"
        )

    if method not in policy.allowed_methods:
        return deny(
            "method_not_allowed"
        )

    return ApiRequestDecision(
        allowed=True,
        reason="authorized",
        normalized_url=normalized_url,
        method=method,
        operation_id=request.operation_id,
    )


def reserve_api_request(
    *,
    state: ApiRequestState,
    decision: ApiRequestDecision,
) -> ApiRequestState:
    """Reserve one request slot after an allowed decision."""

    if not decision.allowed:
        raise PermissionError(
            f"API request denied: {decision.reason}"
        )

    if state.requests_used >= state.max_requests:
        raise PermissionError(
            "API request budget is exhausted."
        )

    return ApiRequestState(
        requests_used=(
            state.requests_used + 1
        ),
        max_requests=state.max_requests,
    )
