"""Strictly read-only local Metasploit MessagePack RPC inspection.

The Metasploit RPC token is equivalent to high-privilege operator access.
This connector accepts only a fixed read-only method allowlist; it never
passes caller-supplied RPC names, module options, exploit jobs or payloads.
Requires verified HTTPS on IPv4 loopback. No automatic server startup.
"""
from __future__ import annotations

from dataclasses import dataclass
import http.client
import importlib
import re
import ssl
from pathlib import Path

MAX_RPC_BYTES = 2 * 1024 * 1024
_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+~-]{0,79}$")
_READ_ONLY_METHODS = frozenset(("core.version", "module.auxiliary", "module.exploits"))


@dataclass(frozen=True)
class MetasploitLocalStatus:
    version: str
    auxiliary_count: int
    exploit_count: int

    def operator_report(self) -> dict:
        return {
            "tool": "metasploit-framework",
            "operation": "local-read-only-rpc-catalogue",
            "execution_status": "succeeded",
            "api_methods": ("core.version", "module.auxiliary", "module.exploits"),
            "tool_version": self.version,
            "auxiliary_module_count": self.auxiliary_count,
            "exploit_module_count": self.exploit_count,
            "modules_executed": 0,
            "evidence_status": "unverified-module-metadata",
            "limitations": (
                "RPC catalogue metadata does not demonstrate vulnerability or exploitability.",
                "No exploit, payload, session, console command or scan was executed.",
            ),
        }


def _codec():
    try:
        return importlib.import_module("msgpack")
    except ImportError as exc:
        raise RuntimeError(
            "Metasploit local RPC requires the optional msgpack runtime"
        ) from exc


def inspect_local_metasploit(
    *,
    port: int = 55553,
    token: str,
    ca_file: str | Path | None = None,
    timeout: float = 4.0,
) -> MetasploitLocalStatus:
    """Call three fixed read-only RPC methods on a locally trusted TLS endpoint."""
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("Invalid Metasploit RPC port")
    if not isinstance(token, str) or not 8 <= len(token) <= 512 or any(
        c in token for c in "\r\n"
    ):
        raise PermissionError("Metasploit RPC token must be supplied through the protected environment")
    if not 0.1 <= timeout <= 10:
        raise ValueError("Invalid Metasploit RPC timeout")
    if ca_file is not None:
        cafile = Path(ca_file).resolve(strict=True)
        if not cafile.is_file() or cafile.stat().st_size > 65536:
            raise ValueError("Invalid trusted Metasploit CA certificate")
        context = ssl.create_default_context(cafile=str(cafile))
    else:
        context = ssl.create_default_context()
    codec = _codec()
    conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=timeout, context=context)
    def rpc(method: str) -> dict:
        if method not in _READ_ONLY_METHODS:
            raise PermissionError("Metasploit RPC method is not approved")
        body = codec.packb([method, token], use_bin_type=True)
        conn.request("POST", "/api/1.0", body=body, headers={
            "Content-Type": "binary/message-pack",
            "Accept": "binary/message-pack",
        })
        response = conn.getresponse()
        if response.status != 200:
            raise RuntimeError(f"Metasploit RPC request failed: HTTP {response.status}")
        raw = response.read(MAX_RPC_BYTES + 1)
        if len(raw) > MAX_RPC_BYTES:
            raise ValueError("Metasploit RPC response exceeds size limit")
        try:
            payload = codec.unpackb(raw, raw=False)
        except (TypeError, ValueError, Exception) as exc:
            raise ValueError("Invalid Metasploit RPC MessagePack result") from exc
        if not isinstance(payload, dict) or payload.get("error") is True:
            raise RuntimeError("Metasploit RPC returned an error")
        return payload
    try:
        version_data = rpc("core.version")
        aux_data = rpc("module.auxiliary")
        exploit_data = rpc("module.exploits")
    finally:
        conn.close()
    version = version_data.get("version")
    auxiliary = aux_data.get("modules")
    exploits = exploit_data.get("modules")
    if not isinstance(version, str) or not _VERSION.fullmatch(version):
        raise ValueError("Invalid Metasploit RPC version")
    for modules in (auxiliary, exploits):
        if not isinstance(modules, list) or len(modules) > 20000 or not all(
            isinstance(module, str) and len(module) <= 256 for module in modules
        ):
            raise ValueError("Invalid Metasploit RPC module inventory")
    return MetasploitLocalStatus(version, len(auxiliary), len(exploits))
