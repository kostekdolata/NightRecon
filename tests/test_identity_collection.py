"""Read-only live identity collection runtime is bounded and authorization-first."""

from __future__ import annotations

from datetime import datetime, timezone
import tempfile
import unittest

from nightrecon_red_engine.identity_collection import (
    DirectoryEntry,
    IdentityCollectionDenied,
    IdentityCollectionLimits,
    IdentityCollectionRequest,
    IdentityProviderCollection,
    collect_authorized_identity_intelligence,
)
from nightrecon_shared_core.contracts import EngagementMetadata
from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy
from nightrecon_shared_core.workspace import LocalWorkspace


class FakeProvider:
    def __init__(self, entries):
        self.entries = entries
        self.calls = 0

    def collect(self, request):
        self.calls += 1
        return self.entries


def workspace(root, *, scope=("dc.example.test",), capabilities=("identity.collect",)):
    item = LocalWorkspace(root)
    item.create_engagement(EngagementMetadata(
        engagement_id="eng-identity",
        name="Identity lab",
        created_at="2026-09-28T00:00:00+00:00",
        authorization_reference="approval://eng-identity",
        status="active",
    ))
    item.set_execution_policy(EngagementExecutionPolicy(
        engagement_id="eng-identity",
        scope=scope,
        valid_from="2026-09-28T00:00:00+00:00",
        valid_until="2026-09-29T00:00:00+00:00",
        max_actions=4,
        permitted_capabilities=capabilities,
    ))
    return item


class IdentityCollectionTests(unittest.TestCase):
    def test_authorized_collection_normalizes_observed_membership(self):
        with tempfile.TemporaryDirectory() as root:
            provider = FakeProvider((
                DirectoryEntry("CN=Alice,DC=example,DC=test", "user", "Alice"),
                DirectoryEntry(
                    "CN=Ops,DC=example,DC=test", "group", "Ops",
                    ("CN=Alice,DC=example,DC=test",),
                ),
            ))
            result = collect_authorized_identity_intelligence(
                workspace(root), provider,
                IdentityCollectionRequest(
                    engagement_id="eng-identity",
                    source_id="ldap-readonly-1",
                    source_type="active-directory",
                    target="dc.example.test",
                ),
                now=datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc),
            )
            self.assertEqual(provider.calls, 1)
            self.assertEqual(result.entry_count, 2)
            self.assertEqual(result.unresolved_members, 0)
            self.assertEqual(len(result.evidence.identities), 1)
            self.assertEqual(len(result.evidence.groups), 1)
            self.assertEqual(len(result.evidence.memberships), 1)
            self.assertFalse(result.truncated)
            self.assertEqual(result.provider_requests, 0)
            self.assertEqual(result.limitations, ())
            self.assertEqual(
                LocalWorkspace(root).execution_policy("eng-identity").actions_used, 1
            )

    def test_provider_completeness_metadata_is_preserved(self):
        with tempfile.TemporaryDirectory() as root:
            provider = FakeProvider(IdentityProviderCollection(
                entries=(
                    DirectoryEntry(
                        "CN=Alice,DC=example,DC=test",
                        "user",
                        "Alice",
                    ),
                ),
                truncated=True,
                request_count=3,
                duration_ms=125,
                limitations=("Provider page ceiling reached.",),
            ))

            result = collect_authorized_identity_intelligence(
                workspace(root),
                provider,
                IdentityCollectionRequest(
                    engagement_id="eng-identity",
                    source_id="ldap-readonly-1",
                    source_type="active-directory",
                    target="dc.example.test",
                ),
                now=datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc),
            )

            self.assertTrue(result.truncated)
            self.assertEqual(result.provider_requests, 3)
            self.assertEqual(result.provider_duration_ms, 125)
            self.assertEqual(
                result.limitations,
                ("Provider page ceiling reached.",),
            )

    def test_denied_collection_never_calls_provider(self):
        with tempfile.TemporaryDirectory() as root:
            provider = FakeProvider(())
            with self.assertRaises(IdentityCollectionDenied) as denied:
                collect_authorized_identity_intelligence(
                    workspace(root), provider,
                    IdentityCollectionRequest(
                        engagement_id="eng-identity",
                        source_id="entra-readonly-1",
                        source_type="entra-id",
                        target="outside.example.test",
                    ),
                    now=datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc),
                )
            self.assertEqual(denied.exception.reason_code, "target_out_of_scope")
            self.assertEqual(provider.calls, 0)

    def test_limits_reject_provider_overflow(self):
        with tempfile.TemporaryDirectory() as root:
            provider = FakeProvider((
                DirectoryEntry("CN=A,DC=example,DC=test", "user", "A"),
                DirectoryEntry("CN=B,DC=example,DC=test", "user", "B"),
            ))
            with self.assertRaisesRegex(ValueError, "max_entries"):
                collect_authorized_identity_intelligence(
                    workspace(root), provider,
                    IdentityCollectionRequest(
                        engagement_id="eng-identity",
                        source_id="ldap-readonly-1",
                        source_type="active-directory",
                        target="dc.example.test",
                        limits=IdentityCollectionLimits(max_entries=1),
                    ),
                    now=datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc),
                )

    def test_provider_entries_reject_user_members_and_duplicate_members(self):
        with self.assertRaises(ValueError):
            DirectoryEntry("CN=A", "user", "A", ("CN=B",))
        with self.assertRaises(ValueError):
            DirectoryEntry("CN=G", "group", "G", ("CN=A", "CN=A"))

    def test_provider_metadata_rejects_invalid_values(self):
        with self.assertRaisesRegex(ValueError, "request_count"):
            IdentityProviderCollection(entries=(), request_count=-1)
        with self.assertRaisesRegex(ValueError, "duration_ms"):
            IdentityProviderCollection(entries=(), duration_ms=-1)
        with self.assertRaisesRegex(ValueError, "limitations"):
            IdentityProviderCollection(entries=(), limitations=("",))


if __name__ == "__main__":
    unittest.main()
