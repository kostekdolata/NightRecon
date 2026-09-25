"""Bounded safe-active web assessment probes for authorized NightRecon targets."""

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

from nightrecon.web_assessment import WebAssessmentFinding
from nightrecon.web_crawl import CrawlPage, normalize_http_url, url_origin


_DEFAULT_USER_AGENT = "NightRecon/0.24 safe-active-web-assessment"
_RISKY_ADVERTISED_METHODS = frozenset(
    {
        "PUT",
        "DELETE",
        "TRACE",
        "CONNECT",
    }
)


@dataclass(frozen=True)
class SafeActiveWebAssessmentResult:
    """Outcome of bounded non-mutating safe-active web probes."""

    findings: tuple[WebAssessmentFinding, ...]
    requests_attempted: int
    successful_probes: int
    max_requests: int
    errors: tuple[str, ...] = ()


class _NoRedirectHandler(HTTPRedirectHandler):
    """Never follow redirects during safe-active assessment probes."""

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


def assess_web_pages_safe_active(
    *,
    pages: tuple[CrawlPage, ...],
    origin: str,
    authorized: bool,
    timeout: float = 5.0,
    max_requests: int = 10,
    user_agent: str = _DEFAULT_USER_AGENT,
    authorization: str | None = None,
    cookie: str | None = None,
    cookie_jar: CookieJar | None = None,
) -> SafeActiveWebAssessmentResult:
    """Issue bounded OPTIONS probes and inspect advertised HTTP methods."""

    if not authorized:
        raise PermissionError(
            "Safe-active web assessment requires explicit authorization."
        )

    if timeout <= 0:
        raise ValueError("timeout must be greater than 0.")

    if max_requests < 1:
        raise ValueError("max_requests must be at least 1.")

    if not isinstance(user_agent, str) or not user_agent.strip():
        raise ValueError("user_agent must be a non-empty string.")

    if authorization is not None and (
        not isinstance(authorization, str)
        or not authorization.strip()
    ):
        raise ValueError(
            "authorization must be a non-empty string when provided."
        )

    if cookie is not None and (
        not isinstance(cookie, str)
        or not cookie.strip()
    ):
        raise ValueError(
            "cookie must be a non-empty string when provided."
        )

    normalized_origin = url_origin(origin)
    candidates: list[str] = []
    seen: set[str] = set()
    errors: list[str] = []

    for page in pages:
        if page.error:
            continue

        try:
            candidate = normalize_http_url(page.url)
        except ValueError as exc:
            errors.append(
                f"invalid_page_url:{page.url}:{exc}"
            )
            continue

        if url_origin(candidate) != normalized_origin:
            errors.append(
                f"outside_authorized_origin:{candidate}"
            )
            continue

        if candidate in seen:
            continue

        seen.add(candidate)
        candidates.append(candidate)

        if len(candidates) >= max_requests:
            break

    findings: list[WebAssessmentFinding] = []
    successful_probes = 0
    requests_attempted = 0
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

    for url in candidates:
        requests_attempted += 1
        headers = {
            "User-Agent": user_agent.strip(),
            "Accept": "*/*",
        }

        if authorization is not None:
            headers["Authorization"] = authorization.strip()

        if cookie is not None:
            headers["Cookie"] = cookie.strip()

        request = Request(
            url,
            headers=headers,
            method="OPTIONS",
        )

        try:
            with opener.open(
                request,
                timeout=timeout,
            ) as response:
                final_url = normalize_http_url(
                    response.geturl()
                )

                if url_origin(final_url) != normalized_origin:
                    errors.append(
                        "outside_authorized_origin_response:"
                        f"{final_url}"
                    )
                    continue

                successful_probes += 1
                allow_header = (
                    response.headers.get("Allow", "")
                    if response.headers is not None
                    else ""
                )
        except (HTTPError, URLError, OSError, ValueError) as exc:
            errors.append(
                f"{url}:{type(exc).__name__}:{exc}"
            )
            continue

        methods = tuple(
            sorted(
                {
                    value.strip().upper()
                    for value in allow_header.split(",")
                    if value.strip()
                }
            )
        )
        risky_methods = tuple(
            method
            for method in methods
            if method in _RISKY_ADVERTISED_METHODS
        )

        if not risky_methods:
            continue

        findings.append(
            WebAssessmentFinding(
                check_id="web.risky-http-methods-advertised",
                title="Potentially risky HTTP methods are advertised",
                severity="low",
                page_url=url,
                evidence=(
                    "OPTIONS Allow header advertised: "
                    + ", ".join(risky_methods)
                ),
            )
        )

    return SafeActiveWebAssessmentResult(
        findings=tuple(findings),
        requests_attempted=requests_attempted,
        successful_probes=successful_probes,
        max_requests=max_requests,
        errors=tuple(errors),
    )
