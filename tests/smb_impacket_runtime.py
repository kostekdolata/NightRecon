"""Compatibility check for the optional Impacket SMB runtime."""

from __future__ import annotations

from importlib.metadata import version
import inspect

from impacket.smbconnection import SMBConnection

from nightrecon.infrastructure_smb_impacket import (
    ImpacketSmbRuntimeFactory,
    _load_impacket_symbols,
)


def main() -> None:
    installed = version(
        "impacket"
    )

    if not installed.startswith(
        "0.13."
    ):
        raise RuntimeError(
            "Unexpected Impacket version: "
            f"{installed}"
        )

    constructor = inspect.signature(
        SMBConnection
    )
    for name in (
        "remoteName",
        "remoteHost",
        "sess_port",
        "timeout",
    ):
        if name not in constructor.parameters:
            raise RuntimeError(
                "Impacket SMBConnection constructor is missing "
                f"{name}."
            )

    login = inspect.signature(
        SMBConnection.login
    )
    for name in (
        "user",
        "password",
        "domain",
        "lmhash",
        "nthash",
        "ntlmFallback",
    ):
        if name not in login.parameters:
            raise RuntimeError(
                "Impacket SMBConnection.login is missing "
                f"{name}."
            )

    for method in (
        "getServerName",
        "getServerDomain",
        "getDialect",
        "isSigningRequired",
        "listShares",
        "setTimeout",
        "close",
    ):
        if not callable(
            getattr(
                SMBConnection,
                method,
                None,
            )
        ):
            raise RuntimeError(
                "Impacket SMBConnection is missing required method: "
                f"{method}"
            )

    symbols = (
        _load_impacket_symbols()
    )

    if (
        symbols.SMBConnection
        is not SMBConnection
    ):
        raise RuntimeError(
            "NightRecon loaded an unexpected SMBConnection class."
        )

    factory = (
        ImpacketSmbRuntimeFactory(
            symbols=symbols
        )
    )

    if "password" in repr(
        factory
    ).lower():
        # The word is acceptable only in the fixed auth-mode label and must
        # never be an actual secret value. Assert the repr shape exactly.
        expected = (
            "ImpacketSmbRuntimeFactory("
            "auth='password-ntlmv2', "
            "ntlmv1_fallback=False, "
            "operations='identity-and-share-enumeration-only')"
        )

        if repr(
            factory
        ) != expected:
            raise RuntimeError(
                "Unexpected SMB runtime representation."
            )


if __name__ == "__main__":
    main()
