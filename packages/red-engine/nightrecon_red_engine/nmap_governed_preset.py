"""Bounded, unprivileged Nmap TCP-connect discovery preset.

No shell, scripting engine, UDP scan, OS fingerprint, NSE or privilege
escalation. Target must be a single literal IP validated by shared policy.
"""
from __future__ import annotations
from pathlib import Path
import ipaddress
from .governed_command_runner import FixedCommand

def bounded_nmap_tcp_connect(*, executable: str | Path, target: str) -> FixedCommand:
    address = ipaddress.ip_address(target)
    if address.is_multicast or address.is_unspecified or address.is_loopback:
        raise ValueError("Unsupported discovery target")
    program = Path(executable)
    if not program.is_absolute() or program.name.lower() not in ("nmap", "nmap.exe"):
        raise ValueError("Nmap executable must be a verified absolute Nmap path")
    if not program.is_file():
        raise FileNotFoundError("Nmap executable unavailable")
    return FixedCommand(
        name="nmap-bounded-connect",
        executable=program,
        arguments=("-sT", "-Pn", "-n", "--max-retries", "1",
                   "--host-timeout", "20s", "--max-rate", "10",
                   "-p", "22,80,443", "-oX", "-", str(address)),
        capability="external.nmap.discovery",
        impact="low", timeout_seconds=30, elevated=False,
    )
