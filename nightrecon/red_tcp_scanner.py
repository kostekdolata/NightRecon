"""Red Night ownership facade for existing bounded TCP scanning."""

from nightrecon.tcp_scanner import TcpPortResult, scan_tcp_port, scan_tcp_ports

__all__ = ["TcpPortResult", "scan_tcp_port", "scan_tcp_ports"]
