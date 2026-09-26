"""Bounded workflow navigation execution for authorized NightRecon targets."""

from __future__ import annotations

from dataclasses import dataclass
from http.cookiejar import CookieJar

from nightrecon.web_crawl import (
    CrawlPage,
    crawl_site,
    normalize_http_url,
    url_origin,
)
from nightrecon.web_workflow import (
    WorkflowAction,
    WorkflowActionKind,
    WorkflowDecision,
    WorkflowState,
    advance_workflow_state,
)


_DEFAULT_USER_AGENT = "NightRecon/0.25 workflow-navigation"


@dataclass(frozen=True)
class WorkflowNavigationResult:
    """Result of one explicitly authorized GET navigation."""

    success: bool
    reason: str
    page: CrawlPage | None
    state: WorkflowState


def execute_workflow_navigation(
    *,
    action: WorkflowAction,
    decision: WorkflowDecision,
    state: WorkflowState,
    origin: str,
    authorized: bool,
    timeout: float = 5.0,
    max_bytes: int = 262_144,
    user_agent: str = _DEFAULT_USER_AGENT,
    authorization: str | None = None,
    cookie_jar: CookieJar | None = None,
) -> WorkflowNavigationResult:
    """Execute one bounded same-origin GET navigation.

    Form submission is structurally unsupported here. This executor delegates
    the single request to the existing bounded crawler with max_pages=1.
    """

    if not authorized:
        raise PermissionError(
            "Workflow navigation requires explicit authorization."
        )

    if not decision.allowed:
        raise PermissionError(
            f"Workflow navigation denied: {decision.reason}"
        )

    if action.kind != WorkflowActionKind.NAVIGATE:
        raise PermissionError(
            "Workflow executor supports navigation actions only."
        )

    method = action.method.strip().upper()

    if method != "GET" or decision.method != "GET":
        raise PermissionError(
            "Workflow executor supports GET navigation only."
        )

    if timeout <= 0:
        raise ValueError(
            "timeout must be greater than 0."
        )

    if max_bytes < 1:
        raise ValueError(
            "max_bytes must be at least 1."
        )

    if not isinstance(user_agent, str) or not user_agent.strip():
        raise ValueError(
            "user_agent must be a non-empty string."
        )

    if authorization is not None and (
        not isinstance(authorization, str)
        or not authorization.strip()
    ):
        raise ValueError(
            "authorization must be a non-empty string when provided."
        )

    normalized_origin = url_origin(origin)
    source = normalize_http_url(
        action.source_url
    )
    target = normalize_http_url(
        action.target_url
    )

    if (
        url_origin(source) != normalized_origin
        or url_origin(target) != normalized_origin
    ):
        raise PermissionError(
            "Workflow navigation is outside the authorized origin."
        )

    if decision.normalized_target_url != target:
        raise ValueError(
            "Workflow decision target does not match action target."
        )

    crawl = crawl_site(
        start_url=target,
        max_pages=1,
        max_bytes_per_page=max_bytes,
        timeout=timeout,
        user_agent=user_agent.strip(),
        authorization=(
            authorization.strip()
            if authorization is not None
            else None
        ),
        cookie=None,
        cookie_jar=cookie_jar,
    )

    page = (
        crawl.pages[0]
        if crawl.pages
        else None
    )

    if page is None:
        return WorkflowNavigationResult(
            success=False,
            reason="no_page_result",
            page=None,
            state=state,
        )

    if page.error:
        return WorkflowNavigationResult(
            success=False,
            reason="navigation_failed",
            page=page,
            state=state,
        )

    advanced = advance_workflow_state(
        state=state,
        action=action,
        decision=decision,
    )

    return WorkflowNavigationResult(
        success=True,
        reason="completed",
        page=page,
        state=advanced,
    )
