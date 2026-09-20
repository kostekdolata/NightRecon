"""Service detection primitives for NightRecon."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import socket


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


def detect_service(
    address: str,
    port: int,
    timeout: float,
) -> ServiceDetectionResult:
    """Connect to an open TCP port and read a bounded passive banner."""

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

        return ServiceDetectionResult(
            address=address,
            port=port,
            service=service,
            banner=banner,
            error_code=0,
)

    finally:
        sock.close()