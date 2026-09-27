"""Narrow Impacket SMB runtime for NightRecon v0.30.

This wrapper deliberately exposes only password login, negotiated server
identity metadata, bounded share enumeration, and close/logoff through the
NightRecon read-only SMB runtime boundary. It does not expose arbitrary
Impacket operations, file APIs, remote execution, hashes, tickets, or Kerberos.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from nightrecon.credential_resolution import (
    ResolvedCredential,
)
from nightrecon.infrastructure_smb import (
    SmbConnectionProfile,
    SmbShareObservation,
)
from nightrecon.infrastructure_smb_adapter import (
    SmbRuntimeSession,
    SmbServerObservation,
)


class ImpacketSmbRuntimeUnavailable(RuntimeError):
    """Raised when the optional Impacket SMB runtime is unavailable."""


@dataclass(frozen=True)
class _ImpacketSymbols:
    SMBConnection: Any
    SMB_DIALECT: Any
    SMB2_DIALECT_002: int
    SMB2_DIALECT_21: int
    SMB2_DIALECT_30: int
    SMB2_DIALECT_302: int
    SMB2_DIALECT_311: int
    SMB2_NEGOTIATE_SIGNING_REQUIRED: int
    STYPE_DISKTREE: int
    STYPE_PRINTQ: int
    STYPE_DEVICE: int
    STYPE_IPC: int
    STYPE_MASK: int


def _load_impacket_symbols(
) -> _ImpacketSymbols:
    try:
        from impacket.smb import SMB_DIALECT
        from impacket.smb3structs import (
            SMB2_DIALECT_002,
            SMB2_DIALECT_21,
            SMB2_DIALECT_30,
            SMB2_DIALECT_302,
            SMB2_DIALECT_311,
            SMB2_NEGOTIATE_SIGNING_REQUIRED,
        )
        from impacket.smbconnection import (
            SMBConnection,
        )
        from impacket.dcerpc.v5.srvs import (
            STYPE_DEVICE,
            STYPE_DISKTREE,
            STYPE_IPC,
            STYPE_MASK,
            STYPE_PRINTQ,
        )
    except ImportError as exc:
        raise ImpacketSmbRuntimeUnavailable(
            "SMB assessment requires the NightRecon smb extra."
        ) from exc

    return _ImpacketSymbols(
        SMBConnection=SMBConnection,
        SMB_DIALECT=SMB_DIALECT,
        SMB2_DIALECT_002=SMB2_DIALECT_002,
        SMB2_DIALECT_21=SMB2_DIALECT_21,
        SMB2_DIALECT_30=SMB2_DIALECT_30,
        SMB2_DIALECT_302=SMB2_DIALECT_302,
        SMB2_DIALECT_311=SMB2_DIALECT_311,
        SMB2_NEGOTIATE_SIGNING_REQUIRED=(
            SMB2_NEGOTIATE_SIGNING_REQUIRED
        ),
        STYPE_DISKTREE=STYPE_DISKTREE,
        STYPE_PRINTQ=STYPE_PRINTQ,
        STYPE_DEVICE=STYPE_DEVICE,
        STYPE_IPC=STYPE_IPC,
        STYPE_MASK=STYPE_MASK,
    )


def _clean_text(
    value: Any,
) -> str:
    if isinstance(
        value,
        bytes,
    ):
        try:
            if (
                len(value) % 2 == 0
                and bytes(
                    [
                        0,
                    ]
                )
                in value
            ):
                text = value.decode(
                    "utf-16-le",
                    errors="replace",
                )
            else:
                text = value.decode(
                    "utf-8",
                    errors="replace",
                )
        except Exception:
            text = ""
    else:
        text = str(
            value
            if value is not None
            else ""
        )

    return text.rstrip(
        chr(
            0
        )
    ).strip()


def _dialect_name(
    dialect: Any,
    symbols: _ImpacketSymbols,
) -> str:
    if dialect == symbols.SMB_DIALECT:
        return "1.0"

    mapping = {
        symbols.SMB2_DIALECT_002: "2.0.2",
        symbols.SMB2_DIALECT_21: "2.1",
        symbols.SMB2_DIALECT_30: "3.0",
        symbols.SMB2_DIALECT_302: "3.0.2",
        symbols.SMB2_DIALECT_311: "3.1.1",
    }

    return mapping.get(
        dialect,
        str(
            dialect
        ),
    )


def _signing_required(
    connection: Any,
    symbols: _ImpacketSymbols,
) -> bool:
    """Determine negotiated signing policy with SMB3 false-positive guard."""

    dialect = connection.getDialect()

    if (
        isinstance(
            dialect,
            int,
        )
        and dialect
        >= symbols.SMB2_DIALECT_30
    ):
        inner = getattr(
            connection,
            "_SMBConnection",
            None,
        )
        connection_state = getattr(
            inner,
            "_Connection",
            None,
        )

        if isinstance(
            connection_state,
            dict,
        ):
            mode = connection_state.get(
                "ServerSecurityMode"
            )

            if isinstance(
                mode,
                int,
            ):
                return bool(
                    mode
                    & symbols.SMB2_NEGOTIATE_SIGNING_REQUIRED
                )

    return bool(
        connection.isSigningRequired()
    )


def _share_type_name(
    raw_type: Any,
    symbols: _ImpacketSymbols,
) -> str:
    try:
        base_type = int(
            raw_type
        ) & symbols.STYPE_MASK
    except (
        TypeError,
        ValueError,
    ):
        return "unknown"

    mapping = {
        symbols.STYPE_DISKTREE: "disk",
        symbols.STYPE_PRINTQ: "print",
        symbols.STYPE_DEVICE: "device",
        symbols.STYPE_IPC: "ipc",
    }

    return mapping.get(
        base_type,
        "unknown",
    )


class _ImpacketSmbSession:
    """Internal runtime session exposing only the NightRecon boundary."""

    def __init__(
        self,
        connection: Any,
        symbols: _ImpacketSymbols,
    ) -> None:
        self._connection = connection
        self._symbols = symbols
        self._closed = False

    def server_identity(
        self,
    ) -> SmbServerObservation:
        return SmbServerObservation(
            server_name=_clean_text(
                self._connection.getServerName()
            ),
            domain_name=_clean_text(
                self._connection.getServerDomain()
            ),
            dialect=_dialect_name(
                self._connection.getDialect(),
                self._symbols,
            ),
            signing_required=(
                _signing_required(
                    self._connection,
                    self._symbols,
                )
            ),
        )

    def list_shares(
        self,
        *,
        max_shares: int,
    ) -> tuple[
        SmbShareObservation,
        ...
    ]:
        raw_shares = (
            self._connection.listShares()
        )

        if len(
            raw_shares
        ) > max_shares:
            raise ValueError(
                "SMB runtime returned more shares than allowed."
            )

        observations: list[
            SmbShareObservation
        ] = []

        for raw_share in raw_shares:
            try:
                raw_name = raw_share[
                    "shi1_netname"
                ]
                raw_type = raw_share[
                    "shi1_type"
                ]
            except Exception as exc:
                raise ValueError(
                    "SMB share response is malformed."
                ) from exc

            observations.append(
                SmbShareObservation(
                    name=_clean_text(
                        raw_name
                    ),
                    share_type=(
                        _share_type_name(
                            raw_type,
                            self._symbols,
                        )
                    ),
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
            self._connection.close()
        except Exception:
            pass


class ImpacketSmbRuntimeFactory:
    """Create one password-authenticated, NTLMv1-disabled SMB session."""

    def __init__(
        self,
        *,
        symbols: _ImpacketSymbols | None = None,
    ) -> None:
        self._symbols = symbols

    def __repr__(
        self,
    ) -> str:
        return (
            "ImpacketSmbRuntimeFactory("
            "auth='password-ntlmv2', "
            "ntlmv1_fallback=False, "
            "operations='identity-and-share-enumeration-only')"
        )

    def _runtime(
        self,
    ) -> _ImpacketSymbols:
        return (
            self._symbols
            if self._symbols is not None
            else _load_impacket_symbols()
        )

    def connect(
        self,
        *,
        target: str,
        profile: SmbConnectionProfile,
        credential: ResolvedCredential,
    ) -> SmbRuntimeSession:
        symbols = self._runtime()
        connection = None

        try:
            connection = (
                symbols.SMBConnection(
                    remoteName=target,
                    remoteHost=target,
                    sess_port=profile.port,
                    timeout=(
                        profile.connect_timeout
                    ),
                )
            )

            with credential.material.reveal_text() as password:
                connection.login(
                    profile.username,
                    password,
                    profile.domain,
                    "",
                    "",
                    False,
                )

            return _ImpacketSmbSession(
                connection,
                symbols,
            )
        except Exception:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass
            raise
