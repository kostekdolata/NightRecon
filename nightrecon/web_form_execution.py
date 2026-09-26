"""Bounded form submission execution for explicitly authorized NightRecon workflows."""

from __future__ import annotations

from dataclasses import dataclass
from http.cookiejar import CookieJar
from typing import Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import (
    HTTPCookieProcessor,
    HTTPRedirectHandler,
    Request,
    build_opener,
)

from nightrecon.web_crawl import (
    normalize_http_url,
    url_origin,
)
from nightrecon.web_form_intent import WorkflowFormIntent
from nightrecon.web_form_submission import FormSubmissionDecision
from nightrecon.web_workflow import WorkflowState


_DEFAULT_USER_AGENT = "NightRecon/0.25 workflow-form-submission"


@dataclass(frozen=True)
class FormSubmissionExecutionResult:
    """Non-secret outcome of one bounded form submission."""

    success: bool
    reason: str
    status: int | None
    byte_count: int
    state: WorkflowState
    submissions_used: int


class _NoRedirectHandler(HTTPRedirectHandler):
    """Never follow redirects during explicit form submission."""

    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl,
    ):
        return None


def execute_form_submission(
    *,
    intent: WorkflowFormIntent,
    decision: FormSubmissionDecision,
    state: WorkflowState,
    field_values: Mapping[str, str],
    submissions_used: int,
    origin: str,
    authorized: bool,
    timeout: float = 5.0,
    max_body_bytes: int = 8_192,
    max_response_bytes: int = 65_536,
    user_agent: str = _DEFAULT_USER_AGENT,
    authorization: str | None = None,
    cookie_jar: CookieJar | None = None,
) -> FormSubmissionExecutionResult:
    """Execute one explicitly approved, bounded same-origin POST."""

    if not authorized:
        raise PermissionError(
            "Form submission requires explicit authorization."
        )

    if not decision.allowed:
        raise PermissionError(
            f"Form submission denied: {decision.reason}"
        )

    if submissions_used < 0:
        raise ValueError(
            "submissions_used cannot be negative."
        )

    if submissions_used != decision.submissions_used:
        raise PermissionError(
            "Form approval is stale for the current submission count."
        )

    if submissions_used >= decision.max_submissions:
        raise PermissionError(
            "Form submission budget is exhausted."
        )

    if state.actions_used >= state.max_actions:
        raise PermissionError(
            "Workflow action budget is exhausted."
        )

    if timeout <= 0:
        raise ValueError(
            "timeout must be greater than 0."
        )

    if max_body_bytes < 1:
        raise ValueError(
            "max_body_bytes must be at least 1."
        )

    if max_response_bytes < 1:
        raise ValueError(
            "max_response_bytes must be at least 1."
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

    method = intent.method.strip().upper()

    if method != "POST" or decision.method != "POST":
        raise PermissionError(
            "Form executor supports POST only."
        )

    action_url = normalize_http_url(
        intent.action_url
    )
    normalized_origin = url_origin(origin)

    if (
        not intent.action_same_origin
        or url_origin(action_url) != normalized_origin
    ):
        raise PermissionError(
            "Form action is outside the authorized origin."
        )

    if decision.action_url != action_url:
        raise ValueError(
            "Form decision action does not match form intent."
        )

    supplied_names = tuple(
        field_values.keys()
    )

    if set(supplied_names) != set(decision.approved_fields):
        raise PermissionError(
            "Submitted form fields do not exactly match approved fields."
        )

    normalized_values: dict[str, str] = {}

    for name in decision.approved_fields:
        value = field_values[name]

        if not isinstance(value, str):
            raise ValueError(
                "Form field values must be strings."
            )

        normalized_values[name] = value

    body = urlencode(
        normalized_values
    ).encode("utf-8")

    if len(body) > max_body_bytes:
        raise ValueError(
            "Encoded form body exceeds max_body_bytes."
        )

    handlers = [
        _NoRedirectHandler(),
    ]

    if cookie_jar is not None:
        handlers.append(
            HTTPCookieProcessor(cookie_jar)
        )

    opener = build_opener(
        *handlers
    )
    headers = {
        "User-Agent": user_agent.strip(),
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    if authorization is not None:
        headers["Authorization"] = authorization.strip()

    request = Request(
        action_url,
        data=body,
        headers=headers,
        method="POST",
    )

    try:
        with opener.open(
            request,
            timeout=timeout,
        ) as response:
            status = getattr(
                response,
                "status",
                None,
            )
            payload = response.read(
                max_response_bytes
            )
    except HTTPError as exc:
        return FormSubmissionExecutionResult(
            success=False,
            reason="http_error",
            status=exc.code,
            byte_count=0,
            state=state,
            submissions_used=submissions_used,
        )
    except (URLError, OSError, ValueError):
        return FormSubmissionExecutionResult(
            success=False,
            reason="request_failed",
            status=None,
            byte_count=0,
            state=state,
            submissions_used=submissions_used,
        )

    if status is None or not 200 <= status < 300:
        return FormSubmissionExecutionResult(
            success=False,
            reason="non_success_status",
            status=status,
            byte_count=len(payload),
            state=state,
            submissions_used=submissions_used,
        )

    visited = state.visited_urls

    if action_url not in visited:
        visited = (
            *visited,
            action_url,
        )

    advanced_state = WorkflowState(
        current_url=action_url,
        visited_urls=visited,
        actions_used=state.actions_used + 1,
        max_actions=state.max_actions,
    )

    return FormSubmissionExecutionResult(
        success=True,
        reason="completed",
        status=status,
        byte_count=len(payload),
        state=advanced_state,
        submissions_used=submissions_used + 1,
    )
