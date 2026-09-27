"""Compatibility re-export for the Red Night TCP scanner engine."""

from nightrecon.red_tcp_scanner import (
    TcpPortResult,
    scan_tcp_port,
    scan_tcp_ports,
)

__all__ = [
    "TcpPortResult",
    "scan_tcp_port",
    "scan_tcp_ports",
]
