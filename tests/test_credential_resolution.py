"""Tests for NightRecon ephemeral credential resolution."""

from __future__ import annotations

import json
import pickle
import unittest
from unittest.mock import patch

from nightrecon.credential_resolution import (
    CredentialBinding,
    CredentialResolutionError,
    EphemeralSecret,
    resolve_credential,
)
from nightrecon.infrastructure_models import (
    CredentialKind,
    CredentialReference,
    CredentialSourceKind,
)


def _reference(
    *,
    source_kind=CredentialSourceKind.ENVIRONMENT,
):
    return CredentialReference(
        credential_id="corp-readonly",
        kind=CredentialKind.PASSWORD,
        source_kind=source_kind,
    )


class CredentialResolutionTests(unittest.TestCase):
    def test_environment_secret_is_ephemeral_and_repr_is_redacted(self):
        secret = "super-sensitive-password"
        binding = CredentialBinding(
            reference=_reference(),
            source_name="NIGHTRECON_TEST_PASSWORD",
        )

        resolved = resolve_credential(
            binding,
            environment={
                "NIGHTRECON_TEST_PASSWORD": secret,
            },
            ttl_seconds=30.0,
        )

        self.assertTrue(
            resolved.material.active
        )
        self.assertNotIn(
            secret,
            repr(
                resolved
            ),
        )
        self.assertNotIn(
            secret,
            repr(
                resolved.material
            ),
        )
        self.assertEqual(
            str(
                resolved.material
            ),
            "<redacted>",
        )

        with resolved.material.reveal_text() as value:
            self.assertEqual(
                value,
                secret,
            )

        self.assertTrue(
            resolved.material.active
        )

        resolved.clear()

        self.assertTrue(
            resolved.material.cleared
        )

        with self.assertRaises(
            CredentialResolutionError
        ):
            with resolved.material.reveal_text():
                pass

    def test_resolved_credential_context_clears_material(self):
        secret = "context-secret"
        binding = CredentialBinding(
            reference=_reference(),
            source_name="NIGHTRECON_CONTEXT_SECRET",
        )

        with resolve_credential(
            binding,
            environment={
                "NIGHTRECON_CONTEXT_SECRET": secret,
            },
        ) as resolved:
            self.assertTrue(
                resolved.material.active
            )

            with resolved.material.reveal_text() as value:
                self.assertEqual(
                    value,
                    secret,
                )

        self.assertTrue(
            resolved.material.cleared
        )
        self.assertNotIn(
            secret,
            repr(
                resolved
            ),
        )

    def test_metadata_is_safe_for_json_logs_and_reports(self):
        secret = "never-persist-this"
        binding = CredentialBinding(
            reference=_reference(),
            source_name="NIGHTRECON_METADATA_SECRET",
        )
        resolved = resolve_credential(
            binding,
            environment={
                "NIGHTRECON_METADATA_SECRET": secret,
            },
        )

        metadata = resolved.metadata()
        serialized = json.dumps(
            metadata,
            sort_keys=True,
        )

        self.assertEqual(
            metadata,
            {
                "credential_id": "corp-readonly",
                "kind": "password",
                "source_kind": "environment",
                "source_name": "NIGHTRECON_METADATA_SECRET",
            },
        )
        self.assertNotIn(
            secret,
            serialized,
        )
        self.assertNotIn(
            "material",
            metadata,
        )

        resolved.clear()

    def test_secret_objects_refuse_pickle_serialization(self):
        material = EphemeralSecret(
            "pickle-secret"
        )
        resolved = resolve_credential(
            CredentialBinding(
                reference=_reference(),
                source_name="NIGHTRECON_PICKLE_SECRET",
            ),
            environment={
                "NIGHTRECON_PICKLE_SECRET": "pickle-secret",
            },
        )

        with self.assertRaises(
            TypeError
        ):
            pickle.dumps(
                material
            )

        with self.assertRaises(
            TypeError
        ):
            pickle.dumps(
                resolved
            )

        material.clear()
        resolved.clear()

    def test_expired_material_is_zeroized_before_reveal(self):
        with patch(
            "nightrecon.credential_resolution.time.monotonic",
            side_effect=[
                100.0,
                102.0,
                102.0,
            ],
        ):
            material = EphemeralSecret(
                "short-lived",
                ttl_seconds=1.0,
            )

            self.assertTrue(
                material.expired
            )

            with self.assertRaisesRegex(
                CredentialResolutionError,
                "expired",
            ):
                with material.reveal_text():
                    pass

        self.assertTrue(
            material.cleared
        )
        self.assertEqual(
            repr(
                material
            ),
            "EphemeralSecret(<redacted>, state=cleared)",
        )

    def test_missing_empty_and_oversized_sources_fail_without_secret_echo(self):
        binding = CredentialBinding(
            reference=_reference(),
            source_name="NIGHTRECON_LIMITED_SECRET",
        )

        for environment in (
            {},
            {
                "NIGHTRECON_LIMITED_SECRET": "",
            },
        ):
            with self.subTest(
                environment=environment
            ):
                with self.assertRaises(
                    CredentialResolutionError
                ) as context:
                    resolve_credential(
                        binding,
                        environment=environment,
                    )

                self.assertNotIn(
                    "secret-value",
                    str(
                        context.exception
                    ),
                )

        oversized = (
            "secret-value"
            * 100
        )

        with self.assertRaises(
            CredentialResolutionError
        ) as context:
            resolve_credential(
                binding,
                environment={
                    "NIGHTRECON_LIMITED_SECRET": oversized,
                },
                max_secret_bytes=8,
            )

        self.assertNotIn(
            oversized,
            str(
                context.exception
            ),
        )

    def test_unsupported_secret_provider_fails_closed(self):
        binding = CredentialBinding(
            reference=_reference(
                source_kind=CredentialSourceKind.EXTERNAL_SECRET,
            ),
            source_name="vault/nightrecon/corp-readonly",
        )

        with self.assertRaisesRegex(
            CredentialResolutionError,
            "not available",
        ):
            resolve_credential(
                binding,
                environment={
                    "vault/nightrecon/corp-readonly": "must-not-be-used",
                },
            )

    def test_binding_rejects_unsafe_source_names(self):
        for source_name in (
            "",
            "HAS SPACE",
            "NAME\nINJECTION",
            "../secret",
        ):
            with self.subTest(
                source_name=source_name
            ):
                with self.assertRaises(
                    ValueError
                ):
                    CredentialBinding(
                        reference=_reference(),
                        source_name=source_name,
                    )

    def test_invalid_secret_handle_limits_fail_closed(self):
        with self.assertRaises(
            ValueError
        ):
            EphemeralSecret(
                "secret",
                ttl_seconds=0,
            )

        with self.assertRaises(
            ValueError
        ):
            EphemeralSecret(
                "secret",
                max_bytes=0,
            )

        with self.assertRaises(
            ValueError
        ):
            EphemeralSecret(
                "",
            )


if __name__ == "__main__":
    unittest.main()
