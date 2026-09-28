"""Bounded safe-active HTTP transport for NightRecon DAST."""

from __future__ import annotations

from dataclasses import dataclass
from http.cookiejar import CookieJar
from urllib.error import HTTPError, URLError
from urllib.request import (
    HTTPCookieProcessor,
    HTTPRedirectHandler,
    Request,
    build_opener,
)

from nightrecon_red_engine.dast_evidence import (
    DastResponseFingerprint,
    fingerprint_response,
    redact_dast_url,
)
from nightrecon_red_engine.dast_policy import (
    DastBudgetPolicy,
    DastBudgetState,
    DastCheckDefinition,
    authorize_dast_request,
    reserve_dast_request,
)
from nightrecon_red_engine.web_crawl import (
    normalize_http_url,
    url_origin,
)


_DEFAULT_USER_AGENT = "NightRecon/0.28 safe-active-dast"
_ALLOWED_SYNTHETIC_HEADERS = frozenset(
    {
        "origin",
        "access-control-request-method",
        "access-control-request-headers",
    }
)
_RETAINED_RESPONSE_HEADERS = frozenset(
    {
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "vary",
        "allow",
    }
)


@dataclass(frozen=True)
class DastHttpResult:
    """Non-secret result of one bounded safe-active HTTP request."""

    success: bool
    reason: str
    url: str
    method: str
    status: int | None
    content_type: str
    response_headers: tuple[
        tuple[str, str],
        ...,
    ]
    fingerprint: DastResponseFingerprint | None
    state: DastBudgetState


class _NoRedirectHandler(
    HTTPRedirectHandler
):
    """Never follow redirects in the generic safe-active DAST transport."""

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


def _validated_synthetic_headers(
    headers: tuple[
        tuple[str, str],
        ...,
    ],
) -> dict[str, str]:
    normalized: dict[
        str,
        str,
    ] = {}

    for raw_name, raw_value in headers:
        name = raw_name.strip().lower()

        if name not in _ALLOWED_SYNTHETIC_HEADERS:
            raise ValueError(
                f"Synthetic DAST header is not allowed: {raw_name}"
            )

        if name in normalized:
            raise ValueError(
                f"Duplicate synthetic DAST header: {raw_name}"
            )

        if (
            not isinstance(
                raw_value,
                str,
            )
            or not raw_value.strip()
        ):
            raise ValueError(
                "Synthetic DAST header values must be non-empty strings."
            )

        value = raw_value.strip()

        if (
            "\r"
            in value
            or "\n"
            in value
        ):
            raise ValueError(
                "Synthetic DAST header values must not contain line breaks."
            )

        normalized[
            name
        ] = value

    return normalized


def _retained_headers(
    headers,
) -> tuple[
    tuple[str, str],
    ...,
]:
    if headers is None:
        return ()

    retained: dict[
        str,
        str,
    ] = {}

    for name, value in headers.items():
        normalized_name = (
            str(name)
            .strip()
            .lower()
        )

        if (
            normalized_name
            not in _RETAINED_RESPONSE_HEADERS
        ):
            continue

        normalized_value = str(
            value
        ).strip()

        if (
            "\r"
            in normalized_value
            or "\n"
            in normalized_value
        ):
            continue

        retained[
            normalized_name
        ] = normalized_value[
            :2048
        ]

    return tuple(
        sorted(
            retained.items()
        )
    )


def execute_dast_http_request(
    *,
    check: DastCheckDefinition,
    url: str,
    method: str,
    origin: str,
    policy: DastBudgetPolicy,
    state: DastBudgetState,
    authorized: bool,
    timeout: float = 5.0,
    max_response_bytes: int = 262_144,
    max_fingerprint_bytes: int = 8192,
    synthetic_headers: tuple[
        tuple[str, str],
        ...,
    ] = (),
    authorization: str | None = None,
    cookie_jar: CookieJar | None = None,
    user_agent: str = _DEFAULT_USER_AGENT,
) -> DastHttpResult:
    """Execute one safe-active GET/HEAD/OPTIONS request under DAST policy."""

    if not authorized:
        raise PermissionError(
            "DAST HTTP execution requires explicit authorization."
        )

    if timeout <= 0:
        raise ValueError(
            "timeout must be greater than 0."
        )

    if max_response_bytes < 1:
        raise ValueError(
            "max_response_bytes must be at least 1."
        )

    if max_fingerprint_bytes < 1:
        raise ValueError(
            "max_fingerprint_bytes must be at least 1."
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
        url
    )
    normalized_origin = url_origin(
        origin
    )

    if url_origin(
        normalized_url
    ) != normalized_origin:
        raise PermissionError(
            "DAST HTTP request is outside the authorized origin."
        )

    normalized_method = (
        method.strip().upper()
    )
    extra_headers = (
        _validated_synthetic_headers(
            synthetic_headers
        )
    )
    decision = authorize_dast_request(
        check=check,
        method=normalized_method,
        policy=policy,
        state=state,
    )

    if not decision.allowed:
        raise PermissionError(
            f"DAST HTTP request denied: {decision.reason}"
        )

    reserved_state = reserve_dast_request(
        state=state,
        decision=decision,
    )
    headers = {
        "User-Agent": user_agent.strip(),
        "Accept": "*/*",
    }

    for name, value in extra_headers.items():
        headers[
            "-".join(
                part.capitalize()
                for part in name.split("-")
            )
        ] = value

    if authorization is not None:
        headers[
            "Authorization"
        ] = authorization.strip()

    handlers = [
        _NoRedirectHandler(),
    ]

    if cookie_jar is not None:
        handlers.append(
            HTTPCookieProcessor(
                cookie_jar
            )
        )

    opener = build_opener(
        *handlers
    )
    request = Request(
        normalized_url,
        headers=headers,
        method=normalized_method,
    )
    redacted_url = redact_dast_url(
        normalized_url
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
            content_type = (
                response.headers.get(
                    "Content-Type",
                    "",
                )
                if response.headers
                is not None
                else ""
            )
            retained_headers = _retained_headers(
                response.headers
            )

            if normalized_method == "HEAD":
                payload = b""
            else:
                payload = response.read(
                    max_response_bytes
                    + 1
                )

                if (
                    len(payload)
                    > max_response_bytes
                ):
                    return DastHttpResult(
                        success=False,
                        reason="response_byte_limit_exceeded",
                        url=redacted_url,
                        method=normalized_method,
                        status=status,
                        content_type=content_type,
                        response_headers=retained_headers,
                        fingerprint=None,
                        state=reserved_state,
                    )

    except HTTPError as exc:
        return DastHttpResult(
            success=False,
            reason="http_error",
            url=redacted_url,
            method=normalized_method,
            status=exc.code,
            content_type=(
                exc.headers.get(
                    "Content-Type",
                    "",
                )
                if exc.headers
                is not None
                else ""
            ),
            response_headers=_retained_headers(
                exc.headers
            ),
            fingerprint=None,
            state=reserved_state,
        )
    except (
        URLError,
        OSError,
        ValueError,
    ):
        return DastHttpResult(
            success=False,
            reason="request_failed",
            url=redacted_url,
            method=normalized_method,
            status=None,
            content_type="",
            response_headers=(),
            fingerprint=None,
            state=reserved_state,
        )

    fingerprint = fingerprint_response(
        status=status,
        content_type=content_type,
        observed_byte_count=len(
            payload
        ),
        body_sample=payload,
        max_sample_bytes=max_fingerprint_bytes,
    )
    success = (
        status is not None
        and 200 <= status < 300
    )

    return DastHttpResult(
        success=success,
        reason=(
            "completed"
            if success
            else "non_success_status"
        ),
        url=redacted_url,
        method=normalized_method,
        status=status,
        content_type=content_type,
        response_headers=retained_headers,
        fingerprint=fingerprint,
        state=reserved_state,
    )
