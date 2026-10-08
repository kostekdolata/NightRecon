"""Scoped HTTP/2 repeater for authorized Red Night testing."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from nightrecon_shared_core.authorization import Scope, parse_target


MAX_HTTP2_REQUEST_BODY = 1_048_576
MAX_HTTP2_RESPONSE_BODY = 2_097_152


class Http2RuntimeUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class Http2RepeaterResponse:
    status: int
    http_version: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    truncated: bool


def _authorize_url(url: str, scope: Scope) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "https":
        raise ValueError("HTTP/2 repeater requires an https URL")
    if not parsed.hostname:
        raise ValueError("URL must include a hostname")
    if not scope.is_authorized(parse_target(parsed.hostname)):
        raise PermissionError(
            f"Target '{parsed.hostname}' is outside the authorized scope."
        )


def replay_http2_request(
    *,
    method: str,
    url: str,
    scope: Scope,
    headers: tuple[tuple[str, str], ...] = (),
    body: bytes = b"",
    timeout: float = 5.0,
) -> Http2RepeaterResponse:
    _authorize_url(url, scope)

    normalized = method.upper()
    if normalized not in {
        "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS",
    }:
        raise ValueError("unsupported HTTP method")
    if len(body) > MAX_HTTP2_REQUEST_BODY:
        raise ValueError("request body exceeds maximum size")
    if timeout <= 0 or timeout > 30:
        raise ValueError("timeout must be between 0 and 30 seconds")

    try:
        import httpx
    except ImportError as exc:
        raise Http2RuntimeUnavailable(
            "HTTP/2 support requires the Red Night http2 extra."
        ) from exc

    data = bytearray()
    truncated = False

    with httpx.Client(
        http2=True,
        timeout=timeout,
        follow_redirects=False,
    ) as client:
        with client.stream(
            normalized,
            url,
            headers=dict(headers),
            content=body or None,
        ) as response:
            for chunk in response.iter_bytes():
                remaining = MAX_HTTP2_RESPONSE_BODY - len(data)
                if remaining <= 0:
                    truncated = True
                    break
                if len(chunk) > remaining:
                    data.extend(chunk[:remaining])
                    truncated = True
                    break
                data.extend(chunk)

            return Http2RepeaterResponse(
                status=response.status_code,
                http_version=response.http_version,
                headers=tuple(response.headers.multi_items()),
                body=bytes(data),
                truncated=truncated,
            )
