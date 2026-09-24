"""Service detection primitives for NightRecon."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import ipaddress
import socket

from nightrecon.security_headers import analyze_security_headers
from nightrecon.tls_detection import probe_tls_service


COMMON_TCP_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
}


@dataclass(frozen=True)
class ServiceDetectionResult:
    """Observed service information for an open TCP port."""

    address: str
    port: int
    service: str
    banner: str
    error_code: int = 0
    http_status: str = ""
    http_server: str = ""
    http_headers: tuple[tuple[str, str], ...] = ()
    security_headers_present: tuple[str, ...] = ()
    security_headers_missing: tuple[str, ...] = ()
    tls_version: str = ""
    tls_cipher: str = ""
    tls_certificate_subject: str = ""
    tls_certificate_issuer: str = ""
    tls_certificate_not_before: str = ""
    tls_certificate_not_after: str = ""
    tls_certificate_sans: tuple[str, ...] = ()
    tls_certificate_sha256: str = ""


@dataclass(frozen=True)
class HttpResponseMetadata:
    """Parsed metadata from a bounded HTTP response."""

    status_line: str
    server: str
    headers: tuple[tuple[str, str], ...] = ()


def identify_service(port: int) -> str:
    """Identify a likely TCP service from its well-known port."""

    if port < 1 or port > 65535:
        raise ValueError("Port must be between 1 and 65535.")

    return COMMON_TCP_SERVICES.get(port, "unknown")


def identify_service_from_banner(banner: str) -> str:
    """Identify a service from an observed passive banner."""

    normalized = banner.strip().lower()

    if normalized.startswith("ssh-"):
        return "ssh"

    if normalized.startswith("220 ") and (
        "ftp" in normalized
        or "proftpd" in normalized
        or "filezilla" in normalized
    ):
        return "ftp"

    if normalized.startswith("220 ") and (
        "smtp" in normalized
        or "esmtp" in normalized
        or "postfix" in normalized
    ):
        return "smtp"

    return "unknown"


def parse_http_response(response: bytes) -> HttpResponseMetadata:
    """Parse basic metadata from a bounded HTTP response."""

    text = response.decode(
        "iso-8859-1",
        errors="replace",
    )

    header_block = text.split("\r\n\r\n", 1)[0]
    lines = header_block.split("\r\n")

    status_line = lines[0].strip() if lines else ""
    server = ""
    headers: list[tuple[str, str]] = []

    for line in lines[1:]:
        name, separator, value = line.partition(":")

        if not separator:
            continue

        header_name = name.strip().lower()
        header_value = value.strip()

        headers.append(
            (header_name, header_value)
        )

        if header_name == "server":
            server = header_value

    return HttpResponseMetadata(
        status_line=status_line,
        server=server,
        headers=tuple(headers),
    )


def probe_http_service(
    address: str,
    port: int,
    timeout: float,
) -> HttpResponseMetadata:
    """Send a bounded HTTP HEAD request and parse response metadata."""

    ip = ipaddress.ip_address(address)

    if port < 1 or port > 65535:
        raise ValueError("Port must be between 1 and 65535.")

    if timeout <= 0:
        raise ValueError("Timeout must be greater than 0.")

    family = (
        socket.AF_INET6
        if isinstance(ip, ipaddress.IPv6Address)
        else socket.AF_INET
    )

    sock = socket.socket(
        family,
        socket.SOCK_STREAM,
    )

    try:
        sock.settimeout(timeout)

        try:
            if family == socket.AF_INET6:
                sock.connect((address, port, 0, 0))
            else:
                sock.connect((address, port))

            request = (
                b"HEAD / HTTP/1.1\r\n"
                + f"Host: {address}\r\n".encode("ascii")
                + b"Connection: close\r\n"
                + b"\r\n"
            )

            sock.sendall(request)

            try:
                response = sock.recv(4096)
            except socket.timeout:
                response = b""

        except OSError:
            response = b""

        return parse_http_response(response)

    finally:
        sock.close()


def detect_service(
    address: str,
    port: int,
    timeout: float,
    server_hostname: str | None = None,
) -> ServiceDetectionResult:
    """Connect to an open TCP port and collect bounded service metadata."""

    ip = ipaddress.ip_address(address)

    if port < 1 or port > 65535:
        raise ValueError("Port must be between 1 and 65535.")

    if timeout <= 0:
        raise ValueError("Timeout must be greater than 0.")

    family = (
        socket.AF_INET6
        if isinstance(ip, ipaddress.IPv6Address)
        else socket.AF_INET
    )

    sock = socket.socket(
        family,
        socket.SOCK_STREAM,
    )

    try:
        sock.settimeout(timeout)

        try:
            if family == socket.AF_INET6:
                sock.connect((address, port, 0, 0))
            else:
                sock.connect((address, port))
        except OSError as exc:
            error_code = (
                exc.errno
                if isinstance(exc.errno, int)
                else -1
            )

            return ServiceDetectionResult(
                address=address,
                port=port,
                service=identify_service(port),
                banner="",
                error_code=error_code,
            )

        try:
            banner_bytes = sock.recv(1024)
        except socket.timeout:
            banner_bytes = b""

        banner = banner_bytes.decode(
            "utf-8",
            errors="replace",
        ).strip()

        banner_service = identify_service_from_banner(banner)

        service = (
            banner_service
            if banner_service != "unknown"
            else identify_service(port)
        )

        http_status = ""
        http_server = ""
        http_headers: tuple[tuple[str, str], ...] = ()
        security_headers_present: tuple[str, ...] = ()
        security_headers_missing: tuple[str, ...] = ()
        tls_version = ""
        tls_cipher = ""
        tls_certificate_subject = ""
        tls_certificate_issuer = ""
        tls_certificate_not_before: str = ""
        tls_certificate_not_after: str = ""
        tls_certificate_sans: tuple[str, ...] = ()
        tls_certificate_sha256: str = ""

        if service in ("http", "http-alt"):
            http_metadata = probe_http_service(
                address=address,
                port=port,
                timeout=timeout,
            )

            http_status = http_metadata.status_line
            http_server = http_metadata.server
            http_headers = http_metadata.headers

        if service == "https":
            tls_metadata = probe_tls_service(
                address=address,
                port=port,
                timeout=timeout,
                server_hostname=server_hostname,
            )

            tls_version = tls_metadata.tls_version
            tls_cipher = tls_metadata.cipher
            tls_certificate_subject = tls_metadata.certificate_subject
            tls_certificate_issuer = tls_metadata.certificate_issuer
            tls_certificate_not_before = tls_metadata.certificate_not_before
            tls_certificate_not_after = tls_metadata.certificate_not_after
            tls_certificate_sans = tls_metadata.certificate_sans
            tls_certificate_sha256 = tls_metadata.certificate_sha256
            http_status = tls_metadata.http_status
            http_server = tls_metadata.http_server
            http_headers = tls_metadata.http_headers

        if http_status:
            header_analysis = analyze_security_headers(
                dict(http_headers)
            )
            security_headers_present = header_analysis.present
            security_headers_missing = header_analysis.missing

        return ServiceDetectionResult(
            address=address,
            port=port,
            service=service,
            banner=banner,
            error_code=0,
            http_status=http_status,
            http_server=http_server,
            http_headers=http_headers,
            security_headers_present=security_headers_present,
            security_headers_missing=security_headers_missing,
            tls_version=tls_version,
            tls_cipher=tls_cipher,
            tls_certificate_subject=tls_certificate_subject,
            tls_certificate_issuer=tls_certificate_issuer,
            tls_certificate_not_before=tls_certificate_not_before,
            tls_certificate_not_after=tls_certificate_not_after,
            tls_certificate_sans=tls_certificate_sans,
            tls_certificate_sha256=tls_certificate_sha256,
        )

    finally:
        sock.close()


def detect_services(
    address: str,
    ports: tuple[int, ...],
    timeout: float,
    max_workers: int = 50,
    server_hostname: str | None = None,
) -> tuple[ServiceDetectionResult, ...]:
    """Detect services concurrently across multiple open TCP ports."""

    if not ports:
        raise ValueError("At least one TCP port is required.")

    if max_workers < 1:
        raise ValueError("max_workers must be at least 1.")

    results: list[ServiceDetectionResult] = []

    with ThreadPoolExecutor(
        max_workers=min(max_workers, len(ports)),
    ) as executor:
        futures = {
            executor.submit(
                detect_service,
                address,
                port,
                timeout,
                server_hostname,
            ): port
            for port in ports
        }

        for future in as_completed(futures):
            results.append(future.result())

    return tuple(
        sorted(
            results,
            key=lambda result: result.port,
        )
    )