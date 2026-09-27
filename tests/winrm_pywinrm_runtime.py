"""Compatibility check for the optional pywinrm runtime."""

from __future__ import annotations

from importlib.metadata import version
import inspect

import winrm
from winrm.protocol import Protocol

from nightrecon.infrastructure_winrm_pywinrm import (
    PyWinRmRuntimeFactory,
    _load_pywinrm_symbols,
)


def main() -> None:
    installed = version(
        "pywinrm"
    )

    if not installed.startswith(
        "0.5."
    ):
        raise RuntimeError(
            "Unexpected pywinrm version: "
            f"{installed}"
        )

    if not getattr(
        winrm,
        "FEATURE_READ_TIMEOUT",
        False,
    ):
        raise RuntimeError(
            "pywinrm read-timeout support is unavailable."
        )

    if not getattr(
        winrm,
        "FEATURE_OPERATION_TIMEOUT",
        False,
    ):
        raise RuntimeError(
            "pywinrm operation-timeout support is unavailable."
        )

    supported = getattr(
        winrm,
        "FEATURE_SUPPORTED_AUTHTYPES",
        (),
    )

    if "ntlm" not in supported:
        raise RuntimeError(
            "pywinrm NTLM transport support is unavailable."
        )

    session_init = inspect.signature(
        winrm.Session.__init__
    )

    for name in (
        "target",
        "auth",
    ):
        if name not in session_init.parameters:
            raise RuntimeError(
                "pywinrm Session constructor is missing "
                f"{name}."
            )

    if not callable(
        getattr(
            winrm.Session,
            "run_ps",
            None,
        )
    ):
        raise RuntimeError(
            "pywinrm Session.run_ps is unavailable."
        )

    protocol_init = inspect.signature(
        Protocol.__init__
    )

    for name in (
        "endpoint",
        "transport",
        "username",
        "password",
        "server_cert_validation",
        "read_timeout_sec",
        "operation_timeout_sec",
        "proxy",
    ):
        if name not in protocol_init.parameters:
            raise RuntimeError(
                "pywinrm Protocol constructor is missing "
                f"{name}."
            )

    symbols = _load_pywinrm_symbols()

    if symbols.Session is not winrm.Session:
        raise RuntimeError(
            "NightRecon loaded an unexpected pywinrm Session class."
        )

    factory = PyWinRmRuntimeFactory(
        symbols=symbols
    )
    expected = (
        "PyWinRmRuntimeFactory("
        "transport='ntlm-over-https', "
        "certificate_validation='required', "
        "proxy='disabled', "
        "operations='fixed-read-only')"
    )

    if repr(
        factory
    ) != expected:
        raise RuntimeError(
            "Unexpected WinRM runtime representation."
        )


if __name__ == "__main__":
    main()
