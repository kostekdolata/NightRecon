"""Backend-neutral browser discovery orchestration for NightRecon.

The worker controller enforces NightRecon browser policy before a backend may
proceed with a request. This module does not import or launch a browser engine.
"""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon.browser_policy import (
    BrowserDiscoveryPolicy,
    BrowserRequest,
    BrowserRequestDecision,
    BrowserResourceKind,
    BrowserWorkerState,
    advance_browser_worker_state,
    authorize_browser_request,
    authorize_dom_snapshot,
    authorize_new_document,
    authorize_response_capture,
)
from nightrecon.web_crawl import normalize_http_url


@dataclass(frozen=True)
class BrowserRequestObservation:
    """Non-secret record of one intercepted browser request."""

    url: str
    method: str
    resource_kind: BrowserResourceKind
    allowed: bool
    reason: str


@dataclass(frozen=True)
class BrowserResponseObservation:
    """Bounded response metadata without response-body retention."""

    url: str
    status: int | None
    byte_count: int
    capture_allowed: bool
    reason: str


@dataclass(frozen=True)
class BrowserDomObservation:
    """Bounded DOM snapshot metadata without storing the snapshot itself."""

    url: str
    byte_count: int
    capture_allowed: bool
    reason: str


@dataclass(frozen=True)
class BrowserDiscoverySnapshot:
    """Current non-secret browser discovery state and evidence."""

    origin: str
    state: BrowserWorkerState
    requests: tuple[BrowserRequestObservation, ...]
    responses: tuple[BrowserResponseObservation, ...]
    dom_snapshots: tuple[BrowserDomObservation, ...]


class BrowserDiscoveryController:
    """Stateful policy controller intended for browser route interception."""

    def __init__(
        self,
        policy: BrowserDiscoveryPolicy,
    ) -> None:
        self._policy = policy
        self._state = BrowserWorkerState(
            requests_used=0,
            pages_used=0,
            runtime_seconds=0.0,
            max_requests=policy.max_requests,
            max_pages=policy.max_pages,
            max_runtime_seconds=policy.max_runtime_seconds,
        )
        self._requests: list[BrowserRequestObservation] = []
        self._responses: list[BrowserResponseObservation] = []
        self._dom_snapshots: list[BrowserDomObservation] = []

    @property
    def policy(self) -> BrowserDiscoveryPolicy:
        return self._policy

    @property
    def state(self) -> BrowserWorkerState:
        return self._state

    def decide_request(
        self,
        *,
        url: str,
        method: str,
        resource_kind: BrowserResourceKind,
        top_level_document: bool = False,
    ) -> BrowserRequestDecision:
        """Decide whether a backend request may proceed."""

        decision = (
            authorize_new_document(
                url=url,
                policy=self._policy,
                state=self._state,
            )
            if top_level_document
            else authorize_browser_request(
                request=BrowserRequest(
                    url=url,
                    method=method,
                    resource_kind=resource_kind,
                ),
                policy=self._policy,
                state=self._state,
            )
        )

        self._requests.append(
            BrowserRequestObservation(
                url=decision.normalized_url,
                method=decision.method,
                resource_kind=decision.resource_kind,
                allowed=decision.allowed,
                reason=decision.reason,
            )
        )
        return decision

    def record_completed_request(
        self,
        *,
        decision: BrowserRequestDecision,
        document_loaded: bool,
        elapsed_seconds: float,
    ) -> BrowserWorkerState:
        """Advance accounting after a backend completed an allowed request."""

        self._state = advance_browser_worker_state(
            state=self._state,
            request_decision=decision,
            document_loaded=document_loaded,
            elapsed_seconds=elapsed_seconds,
        )
        return self._state

    def record_response(
        self,
        *,
        url: str,
        status: int | None,
        byte_count: int,
    ) -> BrowserResponseObservation:
        """Record bounded response metadata."""

        normalized_url = normalize_http_url(url)
        decision = authorize_response_capture(
            byte_count=byte_count,
            policy=self._policy,
        )
        observation = BrowserResponseObservation(
            url=normalized_url,
            status=status,
            byte_count=byte_count,
            capture_allowed=decision.allowed,
            reason=decision.reason,
        )
        self._responses.append(observation)
        return observation

    def record_dom_snapshot(
        self,
        *,
        url: str,
        byte_count: int,
    ) -> BrowserDomObservation:
        """Record whether a serialized DOM snapshot is within policy."""

        normalized_url = normalize_http_url(url)
        decision = authorize_dom_snapshot(
            byte_count=byte_count,
            policy=self._policy,
        )
        observation = BrowserDomObservation(
            url=normalized_url,
            byte_count=byte_count,
            capture_allowed=decision.allowed,
            reason=decision.reason,
        )
        self._dom_snapshots.append(observation)
        return observation

    def snapshot(self) -> BrowserDiscoverySnapshot:
        """Return immutable non-secret worker evidence."""

        return BrowserDiscoverySnapshot(
            origin=self._policy.origin,
            state=self._state,
            requests=tuple(self._requests),
            responses=tuple(self._responses),
            dom_snapshots=tuple(self._dom_snapshots),
        )
