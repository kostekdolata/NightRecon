"""Credential provider boundaries for NightRecon.

Providers return secret text to the ephemeral credential resolver. They do not
perform infrastructure assessment actions and are never serialized or logged.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Mapping, Protocol

from nightrecon_red_engine.infrastructure_models import (
    CredentialSourceKind,
)


class CredentialProvider(Protocol):
    """Secret-source provider contract."""

    @property
    def source_kind(
        self,
    ) -> CredentialSourceKind:
        ...

    def resolve(
        self,
        source_name: str,
    ) -> str:
        ...


@dataclass(frozen=True)
class EnvironmentCredentialProvider:
    """Resolve named values from an environment mapping."""

    environment: Mapping[str, str] | None = None

    @property
    def source_kind(
        self,
    ) -> CredentialSourceKind:
        return (
            CredentialSourceKind.ENVIRONMENT
        )

    def resolve(
        self,
        source_name: str,
    ) -> str:
        source = (
            os.environ
            if self.environment is None
            else self.environment
        )
        value = source.get(
            source_name
        )

        if value is None or not value:
            raise LookupError(
                "Credential source is missing or empty."
            )

        return value


class CredentialProviderRegistry:
    """Exact source-kind registry with duplicate-provider rejection."""

    def __init__(
        self,
        providers: tuple[
            CredentialProvider,
            ...
        ],
    ) -> None:
        if not providers:
            raise ValueError(
                "At least one credential provider is required."
            )

        indexed: dict[
            CredentialSourceKind,
            CredentialProvider,
        ] = {}

        for provider in providers:
            kind = provider.source_kind

            if not isinstance(
                kind,
                CredentialSourceKind,
            ):
                raise ValueError(
                    "Credential provider source_kind is invalid."
                )

            if kind in indexed:
                raise ValueError(
                    "Duplicate credential provider for source kind: "
                    f"{kind.value}"
                )

            indexed[
                kind
            ] = provider

        self._providers = indexed

    def __repr__(
        self,
    ) -> str:
        kinds = ",".join(
            sorted(
                kind.value
                for kind in self._providers
            )
        )
        return (
            "CredentialProviderRegistry("
            f"source_kinds={kinds!r})"
        )

    def provider_for(
        self,
        source_kind: CredentialSourceKind,
    ) -> CredentialProvider:
        try:
            return self._providers[
                source_kind
            ]
        except KeyError as exc:
            raise LookupError(
                "No credential provider is registered for source kind: "
                f"{source_kind.value}"
            ) from exc


def default_credential_provider_registry(
    *,
    environment: Mapping[str, str] | None = None,
) -> CredentialProviderRegistry:
    """Build the default v0.29 registry.

    Only environment-backed resolution is built in. External secret stores and
    OS credential stores require explicit provider objects supplied by the
    caller.
    """

    return CredentialProviderRegistry(
        (
            EnvironmentCredentialProvider(
                environment=environment
            ),
        )
    )
