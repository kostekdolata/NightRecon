"""Bounded HTTP intercept/repeater intelligence for authorized Red Night testing.

The proxy binds to loopback by default, captures metadata rather than secret
header values, and forwards only targets authorized by the supplied Scope.
HTTPS CONNECT interception is optional, loopback-only, scope-gated, and uses
an operator-visible local assessment CA without retaining secret header values.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from urllib.parse import parse_qsl, urlsplit

from nightrecon_red_engine.https_intercept import (
    AssessmentCertificateAuthority,
    authorize_connect_target,
)

from nightrecon_shared_core.authorization import Scope, parse_target


MAX_REQUEST_BODY = 1_048_576
MAX_RESPONSE_BODY = 2_097_152
_ALLOWED_METHODS = frozenset({
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS",
})
_SECRET_HEADER_NAMES = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
})


@dataclass(frozen=True)
class ParameterObservation:
    location: str
    name: str


@dataclass(frozen=True)
class CookieObservation:
    name: str
    secure: bool
    http_only: bool
    same_site: str
    issue: str = ""


@dataclass(frozen=True)
class HttpExchangeRecord:
    exchange_id: str
    method: str
    url: str
    request_header_names: tuple[str, ...]
    request_body_bytes: int
    response_status: int
    response_header_names: tuple[str, ...]
    response_body_bytes: int
    parameters: tuple[ParameterObservation, ...] = ()
    cookies: tuple[CookieObservation, ...] = ()


@dataclass(frozen=True)
class RepeaterResponse:
    status: int
    reason: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    truncated: bool


def _authorized_url(url: str, scope: Scope) -> tuple[str, str, int, str]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("URL scheme must be http or https")
    if not parsed.hostname:
        raise ValueError("URL must include a hostname")
    target = parse_target(parsed.hostname)
    if not scope.is_authorized(target):
        raise PermissionError(
            f"Target '{parsed.hostname}' is outside the authorized scope."
        )
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return parsed.scheme, parsed.hostname, port, path


def discover_parameters(
    *,
    url: str,
    content_type: str = "",
    body: bytes = b"",
) -> tuple[ParameterObservation, ...]:
    observations: set[tuple[str, str]] = set()
    parsed = urlsplit(url)
    for name, _value in parse_qsl(parsed.query, keep_blank_values=True):
        if name:
            observations.add(("query", name))

    lowered = content_type.lower()
    if body and "application/x-www-form-urlencoded" in lowered:
        decoded = body.decode("utf-8", "replace")
        for name, _value in parse_qsl(decoded, keep_blank_values=True):
            if name:
                observations.add(("body-form", name))
    elif body and "application/json" in lowered:
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            payload = None
        if isinstance(payload, dict):
            for name in payload:
                if isinstance(name, str) and name:
                    observations.add(("body-json", name))

    return tuple(
        ParameterObservation(location=location, name=name)
        for location, name in sorted(observations)
    )


def analyze_set_cookie(headers: tuple[tuple[str, str], ...]) -> tuple[CookieObservation, ...]:
    results = []
    for key, value in headers:
        if key.lower() != "set-cookie":
            continue
        parts = [item.strip() for item in value.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name = parts[0].split("=", 1)[0].strip()
        attrs = {item.lower() for item in parts[1:]}
        same_site = ""
        for item in parts[1:]:
            if item.lower().startswith("samesite="):
                same_site = item.split("=", 1)[1].strip()
                break
        secure = "secure" in attrs
        http_only = "httponly" in attrs
        issues = []
        if not secure:
            issues.append("missing Secure")
        if not http_only:
            issues.append("missing HttpOnly")
        if not same_site:
            issues.append("missing SameSite")
        results.append(CookieObservation(
            name=name,
            secure=secure,
            http_only=http_only,
            same_site=same_site,
            issue=", ".join(issues),
        ))
    return tuple(results)


def replay_request(
    *,
    method: str,
    url: str,
    scope: Scope,
    headers: tuple[tuple[str, str], ...] = (),
    body: bytes = b"",
    timeout: float = 5.0,
) -> RepeaterResponse:
    normalized = method.upper()
    if normalized not in _ALLOWED_METHODS:
        raise ValueError("unsupported HTTP method")
    if len(body) > MAX_REQUEST_BODY:
        raise ValueError("request body exceeds maximum size")
    if timeout <= 0 or timeout > 30:
        raise ValueError("timeout must be between 0 and 30 seconds")

    scheme, host, port, path = _authorized_url(url, scope)
    connection_cls = (
        http.client.HTTPSConnection
        if scheme == "https"
        else http.client.HTTPConnection
    )
    connection = connection_cls(host, port, timeout=timeout)
    try:
        connection.request(
            normalized,
            path,
            body=body or None,
            headers=dict(headers),
        )
        response = connection.getresponse()
        data = response.read(MAX_RESPONSE_BODY + 1)
        truncated = len(data) > MAX_RESPONSE_BODY
        if truncated:
            data = data[:MAX_RESPONSE_BODY]
        return RepeaterResponse(
            status=response.status,
            reason=response.reason,
            headers=tuple(response.getheaders()),
            body=data,
            truncated=truncated,
        )
    finally:
        connection.close()


def _safe_record_url(url: str) -> str:
    parsed = urlsplit(url)
    path = parsed.path or "/"
    authority = parsed.netloc
    return f"{parsed.scheme}://{authority}{path}"


def build_exchange_record(
    *,
    method: str,
    url: str,
    request_headers: tuple[tuple[str, str], ...],
    request_body: bytes,
    response: RepeaterResponse,
) -> HttpExchangeRecord:
    request_header_names = tuple(sorted({
        key.lower() for key, _value in request_headers
        if key.lower() not in _SECRET_HEADER_NAMES
    }))
    response_header_names = tuple(sorted({
        key.lower() for key, _value in response.headers
        if key.lower() not in _SECRET_HEADER_NAMES
    }))
    content_type = next(
        (
            value for key, value in request_headers
            if key.lower() == "content-type"
        ),
        "",
    )
    safe_url = _safe_record_url(url)
    material = (
        method.upper()
        + "|"
        + safe_url
        + "|"
        + str(response.status)
        + "|"
        + str(len(request_body))
        + "|"
        + str(len(response.body))
    )
    return HttpExchangeRecord(
        exchange_id="httpx-" + sha256(material.encode()).hexdigest()[:20],
        method=method.upper(),
        url=safe_url,
        request_header_names=request_header_names,
        request_body_bytes=len(request_body),
        response_status=response.status,
        response_header_names=response_header_names,
        response_body_bytes=len(response.body),
        parameters=discover_parameters(
            url=url,
            content_type=content_type,
            body=request_body,
        ),
        cookies=analyze_set_cookie(response.headers),
    )


class _ProxyServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        server_address,
        handler,
        *,
        scope: Scope,
        records: list[HttpExchangeRecord],
        assessment_ca: AssessmentCertificateAuthority | None = None,
    ):
        super().__init__(server_address, handler)
        self.scope = scope
        self.records = records
        self.assessment_ca = assessment_ca


class _ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _forward(self) -> None:
        if self.command not in _ALLOWED_METHODS:
            self.send_error(405)
            return
        mitm_origin = getattr(self, "_mitm_origin", "")
        target_url = (
            mitm_origin + self.path
            if mitm_origin and self.path.startswith("/")
            else self.path
        )
        try:
            content_length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            self.send_error(400)
            return
        if content_length < 0 or content_length > MAX_REQUEST_BODY:
            self.send_error(413)
            return
        body = self.rfile.read(content_length) if content_length else b""
        headers = tuple(
            (key, value)
            for key, value in self.headers.items()
            if key.lower() not in {"proxy-connection", "connection"}
        )
        try:
            response = replay_request(
                method=self.command,
                url=target_url,
                scope=self.server.scope,
                headers=headers,
                body=body,
            )
        except PermissionError:
            self.send_error(403)
            return
        except Exception:
            self.send_error(502)
            return

        record = build_exchange_record(
            method=self.command,
            url=target_url,
            request_headers=headers,
            request_body=body,
            response=response,
        )
        self.server.records.append(record)

        self.send_response(response.status, response.reason)
        for key, value in response.headers:
            lowered = key.lower()
            if lowered in {"transfer-encoding", "connection", "content-length"}:
                continue
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(response.body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(response.body)

    do_GET = _forward
    do_HEAD = _forward
    do_POST = _forward
    do_PUT = _forward
    do_PATCH = _forward
    do_DELETE = _forward
    do_OPTIONS = _forward

    def do_CONNECT(self) -> None:
        assessment_ca = self.server.assessment_ca
        if assessment_ca is None:
            self.send_error(
                501,
                "HTTPS interception is disabled for this proxy instance.",
            )
            return

        authority = self.path.strip()
        if not authority:
            self.send_error(400)
            return

        host = authority
        port = 443
        if authority.startswith("[") and "]" in authority:
            closing = authority.index("]")
            host = authority[1:closing]
            suffix = authority[closing + 1:]
            if suffix.startswith(":"):
                try:
                    port = int(suffix[1:])
                except ValueError:
                    self.send_error(400)
                    return
        elif authority.count(":") == 1:
            candidate_host, candidate_port = authority.rsplit(":", 1)
            try:
                port = int(candidate_port)
                host = candidate_host
            except ValueError:
                host = authority

        try:
            authorize_connect_target(host, port, self.server.scope)
            context = assessment_ca.server_context(host)
        except PermissionError:
            self.send_error(403)
            return
        except (ValueError, OSError):
            self.send_error(400)
            return

        self.connection.sendall(
            b"HTTP/1.1 200 Connection Established\r\n"
            b"Proxy-Agent: RedNight\r\n\r\n"
        )

        try:
            tls_connection = context.wrap_socket(
                self.connection,
                server_side=True,
            )
        except Exception:
            self.close_connection = True
            return

        self.connection = tls_connection
        self.rfile = tls_connection.makefile("rb", self.rbufsize)
        self.wfile = tls_connection.makefile("wb", self.wbufsize)
        host_text = (
            f"[{host}]" if ":" in host else host
        )
        origin = (
            f"https://{host_text}"
            if port == 443
            else f"https://{host_text}:{port}"
        )
        self._mitm_origin = origin
        self.close_connection = False

        try:
            while not self.close_connection:
                self.handle_one_request()
        finally:
            self._mitm_origin = ""
            try:
                self.rfile.close()
            except Exception:
                pass
            try:
                self.wfile.close()
            except Exception:
                pass
            try:
                tls_connection.close()
            except Exception:
                pass
            self.close_connection = True

    def log_message(self, format: str, *args) -> None:
        return


class BoundedInterceptProxy:
    """Loopback HTTP intercept proxy with explicit target scope."""

    def __init__(
        self,
        *,
        scope: Scope,
        host: str = "127.0.0.1",
        port: int = 0,
        https_intercept: bool = False,
        ca_directory: str | None = None,
    ):
        if host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("intercept proxy must bind to loopback")
        self.records: list[HttpExchangeRecord] = []
        self._assessment_ca = (
            AssessmentCertificateAuthority(directory=ca_directory)
            if https_intercept
            else None
        )
        self._server = _ProxyServer(
            (host, port),
            _ProxyHandler,
            scope=scope,
            records=self.records,
            assessment_ca=self._assessment_ca,
        )
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        host, port = self._server.server_address[:2]
        return str(host), int(port)

    @property
    def ca_certificate_path(self) -> str:
        if self._assessment_ca is None:
            return ""
        return str(self._assessment_ca.ca_certificate_path)

    @property
    def ca_fingerprint_sha256(self) -> str:
        if self._assessment_ca is None:
            return ""
        return self._assessment_ca.ca_fingerprint_sha256

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("proxy is already started")
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
        )
        self._thread.start()

    def close(self) -> None:
        if self._thread is not None:
            self._server.shutdown()
            self._thread.join(timeout=2)
            self._thread = None
        self._server.server_close()
        if self._assessment_ca is not None:
            self._assessment_ca.close()
            self._assessment_ca = None

    def __enter__(self) -> "BoundedInterceptProxy":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
