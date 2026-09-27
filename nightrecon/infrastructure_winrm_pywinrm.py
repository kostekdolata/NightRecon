"""Narrow pywinrm runtime for NightRecon v0.30.

This wrapper exposes only the fixed read-only NightRecon WinRM actions through
an already-verified injectable adapter boundary. It does not accept arbitrary
PowerShell, arbitrary commands, registry actions, file transfer, WMI queries
from callers, or caller-supplied script text.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
from typing import Any

from nightrecon.credential_resolution import (
    ResolvedCredential,
)
from nightrecon.infrastructure_winrm import (
    WinRmConnectionProfile,
    WinRmPatchObservation,
    WinRmSystemObservation,
)
from nightrecon.infrastructure_winrm_adapter import (
    WinRmRuntimeSession,
)


_MAX_JSON_BYTES = 262_144

_SYSTEM_IDENTITY_SCRIPT = r"""
$os = Get-CimInstance -ClassName Win32_OperatingSystem
[pscustomobject]@{
    hostname = [string]$env:COMPUTERNAME
    os_name = [string]$os.Caption
    os_version = [string]$os.Version
    architecture = [string]$os.OSArchitecture
} | ConvertTo-Json -Compress
""".strip()

_PATCH_INVENTORY_SCRIPT = r"""
@(Get-HotFix | Select-Object -ExpandProperty HotFixID) | ConvertTo-Json -Compress
""".strip()


class PyWinRmRuntimeUnavailable(RuntimeError):
    """Raised when the optional pywinrm runtime is unavailable."""


class PyWinRmConnectionError(RuntimeError):
    """Secret-safe WinRM connection/authentication failure."""


@dataclass(frozen=True)
class _PyWinRmSymbols:
    Session: Any


def _load_pywinrm_symbols(
) -> _PyWinRmSymbols:
    try:
        import winrm
    except ImportError as exc:
        raise PyWinRmRuntimeUnavailable(
            "WinRM assessment requires the NightRecon winrm extra."
        ) from exc

    return _PyWinRmSymbols(
        Session=winrm.Session,
    )


def _decode_bounded_json(
    value: bytes,
) -> Any:
    if len(value) > _MAX_JSON_BYTES:
        raise ValueError(
            "WinRM response exceeds the bounded JSON output limit."
        )

    try:
        text = value.decode(
            "utf-8"
        )
    except UnicodeDecodeError as exc:
        raise ValueError(
            "WinRM response is not valid UTF-8."
        ) from exc

    try:
        return json.loads(
            text
        )
    except json.JSONDecodeError as exc:
        raise ValueError(
            "WinRM response is not valid JSON."
        ) from exc


class _PyWinRmSession:
    """Internal session exposing only the NightRecon WinRM runtime boundary."""

    def __init__(
        self,
        session: Any,
    ) -> None:
        self._session = session
        self._closed = False

    def _run_fixed_script(
        self,
        script: str,
    ) -> Any:
        response = self._session.run_ps(
            script
        )
        status_code = getattr(
            response,
            "status_code",
            None,
        )

        if status_code != 0:
            raise RuntimeError(
                "WinRM read-only collection failed."
            )

        stdout = getattr(
            response,
            "std_out",
            b"",
        )

        if not isinstance(
            stdout,
            bytes,
        ):
            raise ValueError(
                "WinRM runtime returned invalid output."
            )

        return _decode_bounded_json(
            stdout
        )

    def system_identity(
        self,
    ) -> WinRmSystemObservation:
        data = self._run_fixed_script(
            _SYSTEM_IDENTITY_SCRIPT
        )

        if not isinstance(
            data,
            dict,
        ):
            raise ValueError(
                "WinRM system identity response is malformed."
            )

        try:
            return WinRmSystemObservation(
                hostname=str(
                    data["hostname"]
                ),
                os_name=str(
                    data["os_name"]
                ),
                os_version=str(
                    data["os_version"]
                ),
                architecture=str(
                    data["architecture"]
                ),
            )
        except (
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            raise ValueError(
                "WinRM system identity response is malformed."
            ) from exc

    def list_patches(
        self,
        *,
        max_patches: int,
    ) -> tuple[
        WinRmPatchObservation,
        ...
    ]:
        data = self._run_fixed_script(
            _PATCH_INVENTORY_SCRIPT
        )

        if data is None:
            values: list[Any] = []
        elif isinstance(
            data,
            list,
        ):
            values = data
        else:
            values = [
                data,
            ]

        if len(
            values
        ) > max_patches:
            raise ValueError(
                "WinRM runtime returned more patches than allowed."
            )

        observations: list[
            WinRmPatchObservation
        ] = []

        for value in values:
            if not isinstance(
                value,
                str,
            ):
                raise ValueError(
                    "WinRM patch response is malformed."
                )

            observations.append(
                WinRmPatchObservation(
                    hotfix_id=value,
                )
            )

        return tuple(
            observations
        )

    def close(
        self,
    ) -> None:
        if self._closed:
            return

        self._closed = True

        try:
            protocol = getattr(
                self._session,
                "protocol",
                None,
            )
            transport = getattr(
                protocol,
                "transport",
                None,
            )
            requests_session = getattr(
                transport,
                "session",
                None,
            )

            if requests_session is not None:
                requests_session.close()
        except Exception:
            pass


class PyWinRmRuntimeFactory:
    """Create one HTTPS, certificate-validating NTLM WinRM session."""

    def __init__(
        self,
        *,
        symbols: _PyWinRmSymbols | None = None,
    ) -> None:
        self._symbols = symbols

    def __repr__(
        self,
    ) -> str:
        return (
            "PyWinRmRuntimeFactory("
            "transport='ntlm-over-https', "
            "certificate_validation='required', "
            "proxy='disabled', "
            "operations='fixed-read-only')"
        )

    def _runtime(
        self,
    ) -> _PyWinRmSymbols:
        return (
            self._symbols
            if self._symbols is not None
            else _load_pywinrm_symbols()
        )

    def connect(
        self,
        *,
        target: str,
        profile: WinRmConnectionProfile,
        credential: ResolvedCredential,
    ) -> WinRmRuntimeSession:
        symbols = self._runtime()
        endpoint = (
            f"https://{target}:{profile.port}/wsman"
        )
        operation_timeout = max(
            1,
            math.ceil(
                profile.operation_timeout
            ),
        )
        read_timeout = max(
            math.ceil(
                profile.connect_timeout
            ),
            operation_timeout + 1,
        )

        try:
            with credential.material.reveal_text() as password:
                session = symbols.Session(
                    endpoint,
                    auth=(
                        profile.username,
                        password,
                    ),
                    transport="ntlm",
                    server_cert_validation="validate",
                    read_timeout_sec=read_timeout,
                    operation_timeout_sec=operation_timeout,
                    proxy=None,
                )

            return _PyWinRmSession(
                session
            )
        except Exception:
            raise PyWinRmConnectionError(
                "WinRM runtime connection or authentication setup failed."
            ) from None
