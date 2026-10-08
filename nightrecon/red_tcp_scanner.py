"""Red Night ownership facade for existing bounded TCP scanning."""

from nightrecon.tcp_scanner import (
    MAX_TCP_ATTEMPTS_PER_SCAN,
    MAX_TCP_PORTS_PER_SCAN,
    MAX_TCP_RETRIES,
    MAX_TCP_WORKERS,
    TcpPortResult,
    TcpScanSummary,
    scan_tcp_port,
    scan_tcp_ports,
    summarize_tcp_results,
)

__all__ = [
    "MAX_TCP_ATTEMPTS_PER_SCAN",
    "MAX_TCP_PORTS_PER_SCAN",
    "MAX_TCP_RETRIES",
    "MAX_TCP_WORKERS",
    "TcpPortResult",
    "TcpScanSummary",
    "scan_tcp_port",
    "scan_tcp_ports",
    "summarize_tcp_results",
]
