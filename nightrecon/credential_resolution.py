"""Ephemeral credential resolution for NightRecon infrastructure assessment.

Secret material is kept in short-lived in-memory byte buffers, is never part of
credential metadata models, is redacted from string representations, and can be
explicitly zeroized. This module performs no network activity.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import re
import time
from typing import Iterator, Mapping

from nightrecon.credential_providers import (
    CredentialProviderRegistry,
    default_credential_provider_registry,
)
from nightrecon.infrastructure_models import (
    CredentialReference,
)


_SOURCE_NAME_PATTERN = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_.:/-]{0,255}$"
)


class CredentialResolutionError(RuntimeError):
    """Secret-safe credential resolution failure."""


class EphemeralSecret:
    """Short-lived non-serializable secret buffer."""

    __slots__ = (
        "_buffer",
        "_expires_at",
        "_cleared",
    )

    def __init__(
        self,
        value: str,
        *,
        ttl_seconds: float = 60.0,
        max_bytes: int = 16_384,
    ) -> None:
        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                "Secret material must be text."
            )

        if ttl_seconds <= 0:
            raise ValueError(
                "ttl_seconds must be greater than 0."
            )

        if max_bytes < 1:
            raise ValueError(
                "max_bytes must be at least 1."
            )

        encoded = value.encode(
            "utf-8"
        )

        if not encoded:
            raise ValueError(
                "Secret material must not be empty."
            )

        if len(encoded) > max_bytes:
            raise ValueError(
                "Secret material exceeds the configured byte limit."
            )

        self._buffer = bytearray(
            encoded
        )
        self._expires_at = (
            time.monotonic()
            + ttl_seconds
        )
        self._cleared = False

    def __repr__(self) -> str:
        state = (
            "cleared"
            if self._cleared
            else (
                "expired"
                if self.expired
                else "active"
            )
        )
        return (
            f"EphemeralSecret(<redacted>, state={state})"
        )

    def __str__(self) -> str:
        return "<redacted>"

    def __reduce__(self):
        raise TypeError(
            "EphemeralSecret cannot be serialized."
        )

    @property
    def expired(self) -> bool:
        return (
            not self._cleared
            and time.monotonic()
            >= self._expires_at
        )

    @property
    def active(self) -> bool:
        return (
            not self._cleared
            and not self.expired
        )

    @property
    def cleared(self) -> bool:
        return self._cleared

    def clear(self) -> None:
        """Overwrite the internal buffer and mark this handle unusable."""

        if self._cleared:
            return

        for index in range(
            len(self._buffer)
        ):
            self._buffer[
                index
            ] = 0

        self._buffer.clear()
        self._cleared = True

    def _require_active(self) -> None:
        if self._cleared:
            raise CredentialResolutionError(
                "Credential material has already been cleared."
            )

        if self.expired:
            self.clear()
            raise CredentialResolutionError(
                "Credential material has expired."
            )

    @contextmanager
    def reveal_text(
        self,
    ) -> Iterator[str]:
        """Temporarily decode the active buffer for a bounded consumer."""

        self._require_active()
        value = bytes(
            self._buffer
        ).decode(
            "utf-8"
        )

        try:
            yield value
        finally:
            value = ""


@dataclass(frozen=True)
class CredentialBinding:
    """Maps non-secret credential metadata to a named secret source."""

    reference: CredentialReference
    source_name: str

    def __post_init__(
        self,
    ) -> None:
        normalized = (
            self.source_name.strip()
        )

        if not normalized:
            raise ValueError(
                "source_name must be non-empty."
            )

        if not _SOURCE_NAME_PATTERN.fullmatch(
            normalized
        ):
            raise ValueError(
                "source_name contains unsupported characters."
            )

        object.__setattr__(
            self,
            "source_name",
            normalized,
        )


class ResolvedCredential:
    """Credential metadata plus an ephemeral secret handle."""

    __slots__ = (
        "reference",
        "source_name",
        "material",
    )

    def __init__(
        self,
        *,
        reference: CredentialReference,
        source_name: str,
        material: EphemeralSecret,
    ) -> None:
        self.reference = reference
        self.source_name = source_name
        self.material = material

    def __repr__(self) -> str:
        return (
            "ResolvedCredential("
            f"credential_id={self.reference.credential_id!r}, "
            f"kind={self.reference.kind.value!r}, "
            f"source_kind={self.reference.source_kind.value!r}, "
            f"source_name={self.source_name!r}, "
            "material=<redacted>)"
        )

    def __reduce__(self):
        raise TypeError(
            "ResolvedCredential cannot be serialized."
        )

    def metadata(
        self,
    ) -> dict[str, str]:
        """Return the only representation permitted for logs/reports."""

        return {
            "credential_id": (
                self.reference.credential_id
            ),
            "kind": (
                self.reference.kind.value
            ),
            "source_kind": (
                self.reference.source_kind.value
            ),
            "source_name": self.source_name,
        }

    def clear(self) -> None:
        self.material.clear()

    def __enter__(
        self,
    ) -> "ResolvedCredential":
        return self

    def __exit__(
        self,
        exc_type,
        exc,
        tb,
    ) -> bool:
        self.clear()
        return False


def resolve_credential(
    binding: CredentialBinding,
    *,
    environment: Mapping[str, str] | None = None,
    provider_registry: CredentialProviderRegistry | None = None,
    ttl_seconds: float = 60.0,
    max_secret_bytes: int = 16_384,
) -> ResolvedCredential:
    """Resolve one credential into ephemeral memory.

    The default registry resolves environment-backed credentials only.
    Callers may explicitly supply provider objects for other source kinds.
    All provider output is wrapped in the same ephemeral/redaction contract.
    """

    if (
        environment is not None
        and provider_registry is not None
    ):
        raise ValueError(
            "environment and provider_registry are mutually exclusive."
        )

    registry = (
        provider_registry
        if provider_registry is not None
        else default_credential_provider_registry(
            environment=environment
        )
    )

    try:
        provider = registry.provider_for(
            binding.reference.source_kind
        )
        value = provider.resolve(
            binding.source_name
        )
    except Exception:
        raise CredentialResolutionError(
            "Credential source could not be resolved: "
            f"{binding.source_name}"
        ) from None

    try:
        material = EphemeralSecret(
            value,
            ttl_seconds=ttl_seconds,
            max_bytes=max_secret_bytes,
        )
    except (
        TypeError,
        ValueError,
    ):
        raise CredentialResolutionError(
            "Credential source could not be resolved within safety limits: "
            f"{binding.source_name}"
        ) from None
    finally:
        value = ""

    return ResolvedCredential(
        reference=binding.reference,
        source_name=binding.source_name,
        material=material,
    )
