"""Bounded active service-probe catalog and response matching."""

from __future__ import annotations

from dataclasses import dataclass
import re
import socket

from nightrecon.service_fingerprint import ServiceFingerprint


RAW_PRINT_PORTS = frozenset({9100})


@dataclass(frozen=True)
class ServiceProbeDefinition:
    """One bounded read-only service probe."""

    probe_id: str
    payload: bytes
    rarity: int
    ports: tuple[int, ...] = ()
    max_response_bytes: int = 4096


BUILTIN_SERVICE_PROBES = (
    ServiceProbeDefinition(
        probe_id="http-head",
        payload=(
            b"HEAD / HTTP/1.0\r\n"
            b"Host: nightrecon.invalid\r\n"
            b"Connection: close\r\n\r\n"
        ),
        rarity=1,
        ports=(80, 8000, 8008, 8080, 8081, 8888),
    ),
    ServiceProbeDefinition(
        probe_id="smtp-ehlo",
        payload=b"EHLO nightrecon.invalid\r\n",
        rarity=2,
        ports=(25, 587, 2525),
    ),
    ServiceProbeDefinition(
        probe_id="redis-ping",
        payload=b"PING\r\n",
        rarity=3,
        ports=(6379,),
    ),
    ServiceProbeDefinition(
        probe_id="memcached-version",
        payload=b"version\r\n",
        rarity=3,
        ports=(11211,),
    ),
    ServiceProbeDefinition(
        probe_id="imap-capability",
        payload=b"a001 CAPABILITY\r\n",
        rarity=3,
        ports=(143,),
    ),
    ServiceProbeDefinition(
        probe_id="pop3-capa",
        payload=b"CAPA\r\n",
        rarity=3,
        ports=(110,),
    ),
)


def select_service_probes(
    *,
    port: int,
    intensity: int,
    probes: tuple[
        ServiceProbeDefinition,
        ...,
    ] = BUILTIN_SERVICE_PROBES,
) -> tuple[ServiceProbeDefinition, ...]:
    """Select probes deterministically for one open TCP port."""

    if not 0 <= intensity <= 9:
        raise ValueError(
            "intensity must be between 0 and 9."
        )

    if not 1 <= port <= 65535:
        raise ValueError(
            f"Invalid TCP port: {port}"
        )

    if port in RAW_PRINT_PORTS:
        return ()

    selected = tuple(
        probe
        for probe in probes
        if (
            port in probe.ports
            or probe.rarity <= intensity
        )
    )

    return selected


def probe_tcp_service(
    address: str,
    port: int,
    timeout: float,
    intensity: int,
) -> ServiceFingerprint | None:
    """Run bounded active probes and return the first explicit match."""

    if timeout <= 0:
        raise ValueError(
            "timeout must be greater than 0."
        )

    probes = select_service_probes(
        port=port,
        intensity=intensity,
    )

    for probe in probes:
        sock = None

        try:
            sock = socket.create_connection(
                (address, port),
                timeout=timeout,
            )
            sock.settimeout(timeout)
            sock.sendall(probe.payload)
            response = sock.recv(
                probe.max_response_bytes
            )
        except (
            OSError,
            socket.timeout,
        ):
            continue
        finally:
            if sock is not None:
                sock.close()

        fingerprint = match_service_probe_response(
            probe.probe_id,
            response,
        )

        if fingerprint is not None:
            return fingerprint

    return None


def match_service_probe_response(
    probe_id: str,
    response: bytes,
) -> ServiceFingerprint | None:
    """Match one bounded response without speculative fallback."""

    text = response.decode(
        "latin-1",
        errors="replace",
    ).strip()

    if not text:
        return None

    if probe_id == "http-head":
        return _match_http(text)

    if probe_id == "redis-ping":
        return _match_redis(text)

    if probe_id == "memcached-version":
        return _match_memcached(text)

    if probe_id == "smtp-ehlo":
        return _match_smtp(text)

    if probe_id == "imap-capability":
        return _match_imap(text)

    if probe_id == "pop3-capa":
        return _match_pop3(text)

    return None


def _match_http(
    text: str,
) -> ServiceFingerprint | None:
    lines = text.splitlines()

    if (
        not lines
        or not lines[0].upper().startswith(
            "HTTP/"
        )
    ):
        return None

    for line in lines[1:]:
        name, separator, value = line.partition(":")

        if (
            separator
            and name.strip().lower()
            == "server"
        ):
            server = value.strip()
            product = server
            version = ""

            if "/" in server.split()[0]:
                token = server.split()[0]
                product, version = token.split(
                    "/",
                    1,
                )

            return ServiceFingerprint(
                protocol="http",
                product=product.strip(),
                version=version.strip(),
                source="active-probe:http-head",
                evidence=f"Server: {server}",
                confidence="high",
            )

    return ServiceFingerprint(
        protocol="http",
        source="active-probe:http-head",
        evidence=lines[0].strip(),
        confidence="high",
    )


def _match_redis(
    text: str,
) -> ServiceFingerprint | None:
    first_line = text.splitlines()[0].strip()

    if (
        first_line == "+PONG"
        or first_line.startswith("-NOAUTH")
    ):
        return ServiceFingerprint(
            protocol="redis",
            product="Redis",
            source="active-probe:redis-ping",
            evidence=first_line,
            confidence="high",
        )

    return None


def _match_memcached(
    text: str,
) -> ServiceFingerprint | None:
    first_line = text.splitlines()[0].strip()
    match = re.fullmatch(
        r"VERSION\s+([^\s]+)",
        first_line,
        flags=re.IGNORECASE,
    )

    if match is None:
        return None

    return ServiceFingerprint(
        protocol="memcached",
        product="memcached",
        version=match.group(1),
        source=(
            "active-probe:memcached-version"
        ),
        evidence=first_line,
        confidence="high",
    )


def _match_smtp(
    text: str,
) -> ServiceFingerprint | None:
    first_line = text.splitlines()[0].strip()

    if not re.match(
        r"^(220|250)[ -]",
        first_line,
    ):
        return None

    product = ""

    if "postfix" in text.lower():
        product = "Postfix"
    elif "exim" in text.lower():
        product = "Exim"

    return ServiceFingerprint(
        protocol="smtp",
        product=product,
        source="active-probe:smtp-ehlo",
        evidence=first_line,
        confidence="high",
    )


def _match_imap(
    text: str,
) -> ServiceFingerprint | None:
    normalized = text.upper()

    if (
        "CAPABILITY" not in normalized
        and "IMAP" not in normalized
    ):
        return None

    return ServiceFingerprint(
        protocol="imap",
        source="active-probe:imap-capability",
        evidence=text.splitlines()[0].strip(),
        confidence="high",
    )


def _match_pop3(
    text: str,
) -> ServiceFingerprint | None:
    first_line = text.splitlines()[0].strip()

    if not first_line.upper().startswith(
        "+OK"
    ):
        return None

    return ServiceFingerprint(
        protocol="pop3",
        source="active-probe:pop3-capa",
        evidence=first_line,
        confidence="high",
    )
