"""TCP port specification parsing for NightRecon."""

from __future__ import annotations


MIN_PORT = 1
MAX_PORT = 65535


def parse_ports(value: str) -> tuple[int, ...]:
    """Parse a TCP port specification into a sorted unique tuple."""

    value = value.strip()

    if not value:
        raise ValueError("Port specification cannot be empty.")

    ports: set[int] = set()

    for item in value.split(","):
        item = item.strip()

        if not item:
            raise ValueError("Invalid empty port entry.")

        if "-" in item:
            parts = item.split("-")

            if len(parts) != 2:
                raise ValueError(f"Invalid port range: {item}")

            try:
                start = int(parts[0])
                end = int(parts[1])
            except ValueError as exc:
                raise ValueError(f"Invalid port range: {item}") from exc

            _validate_port(start)
            _validate_port(end)

            if start > end:
                raise ValueError(
                    f"Port range start must not exceed end: {item}"
                )

            ports.update(range(start, end + 1))
            continue

        try:
            port = int(item)
        except ValueError as exc:
            raise ValueError(f"Invalid port: {item}") from exc

        _validate_port(port)
        ports.add(port)

    return tuple(sorted(ports))


def _validate_port(port: int) -> None:
    if port < MIN_PORT or port > MAX_PORT:
        raise ValueError(
            f"Port must be between {MIN_PORT} and {MAX_PORT}: {port}"
        )
