"""Safe workflow-state models and transition policy for NightRecon web assessment."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from nightrecon.web_crawl import (
    CrawlPage,
    normalize_http_url,
    url_origin,
)


class WorkflowActionKind(str, Enum):
    """Kinds of web workflow actions NightRecon may reason about."""

    NAVIGATE = "navigate"
    SUBMIT_FORM = "submit-form"


@dataclass(frozen=True)
class WorkflowAction:
    """One proposed workflow action.

    This model is descriptive only. Constructing an action never sends a
    network request.
    """

    kind: WorkflowActionKind
    source_url: str
    target_url: str
    method: str


@dataclass(frozen=True)
class WorkflowPolicy:
    """Safety policy applied before any future workflow action executes."""

    origin: str
    max_actions: int = 25
    allow_form_submission: bool = False
    allowed_methods: tuple[str, ...] = ("GET",)

    def __post_init__(self) -> None:
        normalized_origin = url_origin(self.origin)

        if self.max_actions < 1:
            raise ValueError("max_actions must be at least 1.")

        methods = tuple(
            method.strip().upper()
            for method in self.allowed_methods
            if isinstance(method, str) and method.strip()
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
class WorkflowState:
    """Immutable execution state for one bounded workflow."""

    current_url: str
    visited_urls: tuple[str, ...]
    actions_used: int
    max_actions: int

    @property
    def actions_remaining(self) -> int:
        return max(
            self.max_actions - self.actions_used,
            0,
        )


@dataclass(frozen=True)
class WorkflowDecision:
    """Authorization decision for one proposed workflow action."""

    allowed: bool
    reason: str
    normalized_source_url: str
    normalized_target_url: str
    method: str


def authorize_workflow_action(
    *,
    action: WorkflowAction,
    policy: WorkflowPolicy,
    actions_used: int,
) -> WorkflowDecision:
    """Validate one proposed action without executing it."""

    if actions_used < 0:
        raise ValueError("actions_used cannot be negative.")

    source = normalize_http_url(
        action.source_url
    )
    target = normalize_http_url(
        action.target_url
    )
    method = action.method.strip().upper()

    if not method:
        raise ValueError(
            "Workflow action method must be non-empty."
        )

    if actions_used >= policy.max_actions:
        return WorkflowDecision(
            allowed=False,
            reason="action_budget_exhausted",
            normalized_source_url=source,
            normalized_target_url=target,
            method=method,
        )

    if (
        url_origin(source) != policy.origin
        or url_origin(target) != policy.origin
    ):
        return WorkflowDecision(
            allowed=False,
            reason="outside_authorized_origin",
            normalized_source_url=source,
            normalized_target_url=target,
            method=method,
        )

    if method not in policy.allowed_methods:
        return WorkflowDecision(
            allowed=False,
            reason="method_not_allowed",
            normalized_source_url=source,
            normalized_target_url=target,
            method=method,
        )

    if (
        action.kind == WorkflowActionKind.SUBMIT_FORM
        and not policy.allow_form_submission
    ):
        return WorkflowDecision(
            allowed=False,
            reason="form_submission_not_enabled",
            normalized_source_url=source,
            normalized_target_url=target,
            method=method,
        )

    return WorkflowDecision(
        allowed=True,
        reason="authorized",
        normalized_source_url=source,
        normalized_target_url=target,
        method=method,
    )


def advance_workflow_state(
    *,
    state: WorkflowState,
    action: WorkflowAction,
    decision: WorkflowDecision,
) -> WorkflowState:
    """Advance immutable workflow state after an already authorized action.

    This function records state only. It performs no network activity.
    """

    if not decision.allowed:
        raise PermissionError(
            f"Workflow transition denied: {decision.reason}"
        )

    if state.actions_used >= state.max_actions:
        raise ValueError(
            "Workflow state action budget is exhausted."
        )

    target = normalize_http_url(
        action.target_url
    )
    method = action.method.strip().upper()

    if decision.normalized_target_url != target:
        raise ValueError(
            "Workflow decision target does not match action target."
        )

    if decision.method != method:
        raise ValueError(
            "Workflow decision method does not match action method."
        )

    visited = state.visited_urls

    if target not in visited:
        visited = (*visited, target)

    return WorkflowState(
        current_url=target,
        visited_urls=visited,
        actions_used=state.actions_used + 1,
        max_actions=state.max_actions,
    )


def build_observed_navigation_plan(
    *,
    pages: tuple[CrawlPage, ...],
    origin: str,
    max_actions: int = 25,
) -> tuple[WorkflowAction, ...]:
    """Build a bounded passive plan from already observed crawl links.

    Forms are deliberately not converted into submission actions. The plan
    contains GET navigation only and performs no network activity.
    """

    if max_actions < 1:
        raise ValueError("max_actions must be at least 1.")

    normalized_origin = url_origin(origin)
    actions: list[WorkflowAction] = []
    seen: set[tuple[str, str]] = set()

    for page in pages:
        if page.error:
            continue

        try:
            source = normalize_http_url(
                page.url
            )
        except ValueError:
            continue

        if url_origin(source) != normalized_origin:
            continue

        for link in page.links:
            try:
                target = normalize_http_url(
                    link
                )
            except ValueError:
                continue

            if url_origin(target) != normalized_origin:
                continue

            key = (source, target)

            if key in seen:
                continue

            seen.add(key)
            actions.append(
                WorkflowAction(
                    kind=WorkflowActionKind.NAVIGATE,
                    source_url=source,
                    target_url=target,
                    method="GET",
                )
            )

            if len(actions) >= max_actions:
                return tuple(actions)

    return tuple(actions)
