"""Safety policy and immutable state for NightRecon browser discovery.

This module contains policy only. It launches no browser, executes no
JavaScript, and performs no network activity.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from nightrecon.web_crawl import normalize_http_url, url_origin


class BrowserResourceKind(str, Enum):
    """Observed browser request categories."""

    DOCUMENT = "document"
    SCRIPT = "script"
    STYLESHEET = "stylesheet"
    XHR = "xhr"
    FETCH = "fetch"
    IMAGE = "image"
    FONT = "font"
    OTHER = "other"


@dataclass(frozen=True)
class BrowserDiscoveryPolicy:
    """Fail-closed limits for one future browser worker."""

    origin: str
    max_requests: int = 100
    max_pages: int = 10
    max_runtime_seconds: float = 30.0
    max_response_bytes: int = 1_048_576
    max_dom_bytes: int = 2_097_152
    max_dom_items: int = 500
    allowed_methods: tuple[str, ...] = ("GET", "HEAD")

    def __post_init__(self) -> None:
        normalized_origin = url_origin(self.origin)

        if self.max_requests < 1:
            raise ValueError(
                "max_requests must be at least 1."
            )

        if self.max_pages < 1:
            raise ValueError(
                "max_pages must be at least 1."
            )

        if self.max_runtime_seconds <= 0:
            raise ValueError(
                "max_runtime_seconds must be greater than 0."
            )

        if self.max_response_bytes < 1:
            raise ValueError(
                "max_response_bytes must be at least 1."
            )

        if self.max_dom_bytes < 1:
            raise ValueError(
                "max_dom_bytes must be at least 1."
            )

        if self.max_dom_items < 1:
            raise ValueError(
                "max_dom_items must be at least 1."
            )

        methods = tuple(
            dict.fromkeys(
                method.strip().upper()
                for method in self.allowed_methods
                if isinstance(method, str) and method.strip()
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
class BrowserWorkerState:
    """Immutable browser-worker accounting state."""

    requests_used: int
    pages_used: int
    runtime_seconds: float
    max_requests: int
    max_pages: int
    max_runtime_seconds: float

    @property
    def requests_remaining(self) -> int:
        return max(
            self.max_requests - self.requests_used,
            0,
        )

    @property
    def pages_remaining(self) -> int:
        return max(
            self.max_pages - self.pages_used,
            0,
        )

    @property
    def runtime_remaining(self) -> float:
        return max(
            self.max_runtime_seconds - self.runtime_seconds,
            0.0,
        )


@dataclass(frozen=True)
class BrowserRequest:
    """One proposed browser network request."""

    url: str
    method: str
    resource_kind: BrowserResourceKind


@dataclass(frozen=True)
class BrowserRequestDecision:
    """Authorization decision made before a browser request proceeds."""

    allowed: bool
    reason: str
    normalized_url: str
    method: str
    resource_kind: BrowserResourceKind


@dataclass(frozen=True)
class BrowserContentDecision:
    """Decision for one captured response or DOM snapshot size."""

    allowed: bool
    reason: str
    byte_count: int
    max_bytes: int


def authorize_response_capture(
    *,
    byte_count: int,
    policy: BrowserDiscoveryPolicy,
) -> BrowserContentDecision:
    """Authorize bounded response capture without reading network data."""

    if byte_count < 0:
        raise ValueError(
            "byte_count cannot be negative."
        )

    return BrowserContentDecision(
        allowed=byte_count <= policy.max_response_bytes,
        reason=(
            "authorized"
            if byte_count <= policy.max_response_bytes
            else "response_byte_limit_exceeded"
        ),
        byte_count=byte_count,
        max_bytes=policy.max_response_bytes,
    )


def authorize_dom_snapshot(
    *,
    byte_count: int,
    policy: BrowserDiscoveryPolicy,
) -> BrowserContentDecision:
    """Authorize bounded serialized DOM retention."""

    if byte_count < 0:
        raise ValueError(
            "byte_count cannot be negative."
        )

    return BrowserContentDecision(
        allowed=byte_count <= policy.max_dom_bytes,
        reason=(
            "authorized"
            if byte_count <= policy.max_dom_bytes
            else "dom_byte_limit_exceeded"
        ),
        byte_count=byte_count,
        max_bytes=policy.max_dom_bytes,
    )


def authorize_browser_request(
    *,
    request: BrowserRequest,
    policy: BrowserDiscoveryPolicy,
    state: BrowserWorkerState,
) -> BrowserRequestDecision:
    """Authorize one proposed browser request without executing it."""

    if state.requests_used < 0:
        raise ValueError(
            "requests_used cannot be negative."
        )

    if state.pages_used < 0:
        raise ValueError(
            "pages_used cannot be negative."
        )

    if state.runtime_seconds < 0:
        raise ValueError(
            "runtime_seconds cannot be negative."
        )

    normalized_url = normalize_http_url(
        request.url
    )
    method = request.method.strip().upper()

    if not method:
        raise ValueError(
            "Browser request method must be non-empty."
        )

    def deny(reason: str) -> BrowserRequestDecision:
        return BrowserRequestDecision(
            allowed=False,
            reason=reason,
            normalized_url=normalized_url,
            method=method,
            resource_kind=request.resource_kind,
        )

    if state.requests_used >= policy.max_requests:
        return deny(
            "request_budget_exhausted"
        )

    if state.runtime_seconds >= policy.max_runtime_seconds:
        return deny(
            "runtime_budget_exhausted"
        )

    if url_origin(normalized_url) != policy.origin:
        return deny(
            "outside_authorized_origin"
        )

    if method not in policy.allowed_methods:
        return deny(
            "method_not_allowed"
        )

    return BrowserRequestDecision(
        allowed=True,
        reason="authorized",
        normalized_url=normalized_url,
        method=method,
        resource_kind=request.resource_kind,
    )


def authorize_new_document(
    *,
    url: str,
    policy: BrowserDiscoveryPolicy,
    state: BrowserWorkerState,
) -> BrowserRequestDecision:
    """Authorize one new top-level document navigation."""

    normalized_url = normalize_http_url(
        url
    )

    if state.pages_used >= policy.max_pages:
        return BrowserRequestDecision(
            allowed=False,
            reason="page_budget_exhausted",
            normalized_url=normalized_url,
            method="GET",
            resource_kind=BrowserResourceKind.DOCUMENT,
        )

    return authorize_browser_request(
        request=BrowserRequest(
            url=normalized_url,
            method="GET",
            resource_kind=BrowserResourceKind.DOCUMENT,
        ),
        policy=policy,
        state=state,
    )


def advance_browser_worker_state(
    *,
    state: BrowserWorkerState,
    request_decision: BrowserRequestDecision,
    document_loaded: bool,
    elapsed_seconds: float,
) -> BrowserWorkerState:
    """Record one already-authorized browser request without performing I/O."""

    if not request_decision.allowed:
        raise PermissionError(
            f"Browser request denied: {request_decision.reason}"
        )

    if elapsed_seconds < 0:
        raise ValueError(
            "elapsed_seconds cannot be negative."
        )

    requests_used = state.requests_used + 1
    pages_used = (
        state.pages_used + 1
        if document_loaded
        else state.pages_used
    )
    runtime_seconds = (
        state.runtime_seconds + elapsed_seconds
    )

    if requests_used > state.max_requests:
        raise ValueError(
            "Browser request budget exceeded."
        )

    if pages_used > state.max_pages:
        raise ValueError(
            "Browser page budget exceeded."
        )

    if runtime_seconds > state.max_runtime_seconds:
        raise ValueError(
            "Browser runtime budget exceeded."
        )

    return BrowserWorkerState(
        requests_used=requests_used,
        pages_used=pages_used,
        runtime_seconds=runtime_seconds,
        max_requests=state.max_requests,
        max_pages=state.max_pages,
        max_runtime_seconds=state.max_runtime_seconds,
    )
