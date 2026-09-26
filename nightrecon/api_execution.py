"""Bounded safe API request execution for NightRecon."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
)

from nightrecon.api_policy import (
    ApiRequest,
    ApiRequestDecision,
    ApiRequestState,
    reserve_api_request,
)
from nightrecon.web_crawl import (
    normalize_http_url,
    url_origin,
)


_DEFAULT_USER_AGENT = "NightRecon/0.27 api-validation"


@dataclass(frozen=True)
class ApiExecutionResult:
    """Non-secret outcome of one bounded API request."""

    success: bool
    reason: str
    url: str
    method: str
    operation_id: str
    status: int | None
    content_type: str
    byte_count: int
    state: ApiRequestState


class _NoRedirectHandler(
    HTTPRedirectHandler
):
    """Never follow redirects during bounded API validation."""

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


def execute_api_request(
    *,
    request: ApiRequest,
    decision: ApiRequestDecision,
    state: ApiRequestState,
    origin: str,
    authorized: bool,
    timeout: float = 5.0,
    max_response_bytes: int = 1_048_576,
    user_agent: str = _DEFAULT_USER_AGENT,
    authorization: str | None = None,
) -> ApiExecutionResult:
    """Execute one already-authorized GET/HEAD API request."""

    if not authorized:
        raise PermissionError(
            "API execution requires explicit authorization."
        )

    if not decision.allowed:
        raise PermissionError(
            f"API request denied: {decision.reason}"
        )

    if timeout <= 0:
        raise ValueError(
            "timeout must be greater than 0."
        )

    if max_response_bytes < 1:
        raise ValueError(
            "max_response_bytes must be at least 1."
        )

    if (
        not isinstance(
            user_agent,
            str,
        )
        or not user_agent.strip()
    ):
        raise ValueError(
            "user_agent must be a non-empty string."
        )

    if authorization is not None and (
        not isinstance(
            authorization,
            str,
        )
        or not authorization.strip()
    ):
        raise ValueError(
            "authorization must be a non-empty string when provided."
        )

    normalized_url = normalize_http_url(
        request.url
    )
    normalized_origin = url_origin(
        origin
    )
    method = request.method.strip().upper()

    if method not in {
        "GET",
        "HEAD",
    }:
        raise PermissionError(
            "API executor supports GET and HEAD only."
        )

    if decision.method != method:
        raise ValueError(
            "API decision method does not match request method."
        )

    if (
        decision.normalized_url
        != normalized_url
    ):
        raise ValueError(
            "API decision URL does not match request URL."
        )

    if url_origin(
        normalized_url
    ) != normalized_origin:
        raise PermissionError(
            "API request is outside the authorized origin."
        )

    reserved_state = reserve_api_request(
        state=state,
        decision=decision,
    )

    headers = {
        "User-Agent": user_agent.strip(),
        "Accept": "application/json, */*;q=0.1",
    }

    if authorization is not None:
        headers[
            "Authorization"
        ] = authorization.strip()

    opener = build_opener(
        _NoRedirectHandler()
    )
    urllib_request = Request(
        normalized_url,
        headers=headers,
        method=method,
    )

    try:
        with opener.open(
            urllib_request,
            timeout=timeout,
        ) as response:
            status = getattr(
                response,
                "status",
                None,
            )
            content_type = (
                response.headers.get(
                    "Content-Type",
                    "",
                )
                if response.headers
                is not None
                else ""
            )

            if method == "HEAD":
                byte_count = 0
            else:
                payload = response.read(
                    max_response_bytes + 1
                )
                byte_count = min(
                    len(payload),
                    max_response_bytes,
                )

                if (
                    len(payload)
                    > max_response_bytes
                ):
                    return ApiExecutionResult(
                        success=False,
                        reason="response_byte_limit_exceeded",
                        url=normalized_url,
                        method=method,
                        operation_id=request.operation_id,
                        status=status,
                        content_type=content_type,
                        byte_count=byte_count,
                        state=reserved_state,
                    )

    except HTTPError as exc:
        return ApiExecutionResult(
            success=False,
            reason="http_error",
            url=normalized_url,
            method=method,
            operation_id=request.operation_id,
            status=exc.code,
            content_type="",
            byte_count=0,
            state=reserved_state,
        )
    except (
        URLError,
        OSError,
        ValueError,
    ):
        return ApiExecutionResult(
            success=False,
            reason="request_failed",
            url=normalized_url,
            method=method,
            operation_id=request.operation_id,
            status=None,
            content_type="",
            byte_count=0,
            state=reserved_state,
        )

    success = (
        status is not None
        and 200 <= status < 300
    )

    return ApiExecutionResult(
        success=success,
        reason=(
            "completed"
            if success
            else "non_success_status"
        ),
        url=normalized_url,
        method=method,
        operation_id=request.operation_id,
        status=status,
        content_type=content_type,
        byte_count=byte_count,
        state=reserved_state,
    )
