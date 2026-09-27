"""Tests for NightRecon credential provider boundaries."""

import unittest

from nightrecon.credential_providers import (
    CredentialProviderRegistry,
    EnvironmentCredentialProvider,
    default_credential_provider_registry,
)
from nightrecon.credential_resolution import (
    CredentialBinding,
    CredentialResolutionError,
    resolve_credential,
)
from nightrecon.infrastructure_models import (
    CredentialKind,
    CredentialReference,
    CredentialSourceKind,
)


class _ExternalProvider:
    source_kind = (
        CredentialSourceKind.EXTERNAL_SECRET
    )

    def __init__(
        self,
        *,
        value="external-provider-secret",
        fail=False,
    ):
        self.value = value
        self.fail = fail
        self.requests = []

    def resolve(
        self,
        source_name,
    ):
        self.requests.append(
            source_name
        )

        if self.fail:
            raise RuntimeError(
                "provider leaked external-provider-secret"
            )

        return self.value


def _binding(
    source_kind,
    source_name="vault/nightrecon/read-only",
):
    return CredentialBinding(
        reference=CredentialReference(
            credential_id="corp-readonly",
            kind=CredentialKind.PASSWORD,
            source_kind=source_kind,
        ),
        source_name=source_name,
    )


class CredentialProviderTests(unittest.TestCase):
    def test_environment_provider_reads_named_value_only(self):
        provider = EnvironmentCredentialProvider(
            environment={
                "NIGHTRECON_ENV_SECRET": "env-secret",
            }
        )

        self.assertEqual(
            provider.source_kind,
            CredentialSourceKind.ENVIRONMENT,
        )
        self.assertEqual(
            provider.resolve(
                "NIGHTRECON_ENV_SECRET"
            ),
            "env-secret",
        )

        with self.assertRaises(
            LookupError
        ):
            provider.resolve(
                "MISSING"
            )

    def test_registry_rejects_duplicate_source_kinds(self):
        with self.assertRaisesRegex(
            ValueError,
            "Duplicate credential provider",
        ):
            CredentialProviderRegistry(
                (
                    EnvironmentCredentialProvider(
                        environment={}
                    ),
                    EnvironmentCredentialProvider(
                        environment={}
                    ),
                )
            )

    def test_default_registry_contains_environment_only(self):
        registry = default_credential_provider_registry(
            environment={
                "NIGHTRECON_DEFAULT_SECRET": "secret",
            }
        )

        provider = registry.provider_for(
            CredentialSourceKind.ENVIRONMENT
        )

        self.assertEqual(
            provider.resolve(
                "NIGHTRECON_DEFAULT_SECRET"
            ),
            "secret",
        )

        with self.assertRaises(
            LookupError
        ):
            registry.provider_for(
                CredentialSourceKind.EXTERNAL_SECRET
            )

        self.assertNotIn(
            "secret",
            repr(
                registry
            ),
        )

    def test_explicit_external_provider_uses_same_ephemeral_contract(self):
        provider = _ExternalProvider()
        registry = CredentialProviderRegistry(
            (
                provider,
            )
        )
        binding = _binding(
            CredentialSourceKind.EXTERNAL_SECRET
        )

        resolved = resolve_credential(
            binding,
            provider_registry=registry,
            ttl_seconds=30.0,
        )

        self.assertEqual(
            provider.requests,
            [
                "vault/nightrecon/read-only",
            ],
        )
        self.assertNotIn(
            "external-provider-secret",
            repr(
                resolved
            ),
        )

        with resolved.material.reveal_text() as value:
            self.assertEqual(
                value,
                "external-provider-secret",
            )

        resolved.clear()

    def test_provider_failure_is_sanitized(self):
        provider = _ExternalProvider(
            fail=True
        )
        registry = CredentialProviderRegistry(
            (
                provider,
            )
        )
        binding = _binding(
            CredentialSourceKind.EXTERNAL_SECRET
        )

        with self.assertRaises(
            CredentialResolutionError
        ) as context:
            resolve_credential(
                binding,
                provider_registry=registry,
            )

        self.assertNotIn(
            "external-provider-secret",
            str(
                context.exception
            ),
        )
        self.assertNotIn(
            "provider leaked",
            str(
                context.exception
            ),
        )

    def test_environment_and_registry_are_mutually_exclusive(self):
        registry = CredentialProviderRegistry(
            (
                _ExternalProvider(),
            )
        )

        with self.assertRaisesRegex(
            ValueError,
            "mutually exclusive",
        ):
            resolve_credential(
                _binding(
                    CredentialSourceKind.EXTERNAL_SECRET
                ),
                environment={},
                provider_registry=registry,
            )


if __name__ == "__main__":
    unittest.main()
