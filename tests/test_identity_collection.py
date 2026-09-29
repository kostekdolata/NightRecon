"""Read-only live identity collection runtime is bounded and authorization-first."""

from __future__ import annotations

from datetime import datetime, timezone
import tempfile
import unittest

from nightrecon_red_engine.graph_identity_evidence import (
    IdentityEvidenceBundle,
    IdentityRelationshipEvidence,
    RoleEvidence,
)
from nightrecon_red_engine.graph_models import GraphNodeKind
from nightrecon_red_engine.red_directory_import import directory_natural_key
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

    def test_computer_and_service_entries_normalize_as_identity_types(self):
        with tempfile.TemporaryDirectory() as root:
            computer_dn = "CN=WS01,OU=Computers,DC=example,DC=test"
            service_dn = "CN=WebSvc,OU=Services,DC=example,DC=test"
            group_dn = "CN=Operators,OU=Groups,DC=example,DC=test"
            provider = FakeProvider((
                DirectoryEntry(
                    computer_dn,
                    "computer",
                    "ws01.example.test",
                    properties=(("dns_hostname", "ws01.example.test"),),
                ),
                DirectoryEntry(
                    service_dn,
                    "service",
                    "Web Service",
                    properties=(("spn_hosts", "web.example.test"),),
                ),
                DirectoryEntry(
                    group_dn,
                    "group",
                    "Operators",
                    (computer_dn, service_dn),
                ),
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

            self.assertEqual(
                {item.identity_type for item in result.evidence.identities},
                {"ad-computer", "ad-service"},
            )
            self.assertEqual(len(result.evidence.memberships), 2)
            properties_by_type = {
                item.identity_type: dict(item.properties)
                for item in result.evidence.identities
            }
            self.assertEqual(
                properties_by_type["ad-computer"]["dns_hostname"],
                "ws01.example.test",
            )
            self.assertEqual(
                properties_by_type["ad-service"]["spn_hosts"],
                "web.example.test",
            )
            self.assertEqual(result.unresolved_members, 0)

    def test_entra_collection_uses_separate_identity_namespace(self):
        with tempfile.TemporaryDirectory() as root:
            object_id = "11111111-1111-1111-1111-111111111111"
            group_id = "22222222-2222-2222-2222-222222222222"
            provider = FakeProvider((
                DirectoryEntry(object_id, "user", "Cloud User"),
                DirectoryEntry(group_id, "group", "Cloud Group", (object_id,)),
            ))

            result = collect_authorized_identity_intelligence(
                workspace(root, scope=("tenant.example",)),
                provider,
                IdentityCollectionRequest(
                    engagement_id="eng-identity",
                    source_id="graph-readonly-1",
                    source_type="entra-id",
                    target="tenant.example",
                ),
                now=datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc),
            )

            self.assertEqual(
                {item.identity_type for item in result.evidence.identities},
                {"entra-user"},
            )
            self.assertTrue(
                result.evidence.identities[0].natural_key.startswith("entra:user:")
            )
            self.assertTrue(
                result.evidence.groups[0].natural_key.startswith("entra:group:")
            )
            self.assertEqual(len(result.evidence.memberships), 1)

    def test_entra_application_and_supplemental_relationships_are_merged(self):
        with tempfile.TemporaryDirectory() as root:
            user_id = "11111111-1111-1111-1111-111111111111"
            app_id = "22222222-2222-2222-2222-222222222222"
            role_key = directory_natural_key(
                "role",
                "33333333-3333-3333-3333-333333333333",
                namespace="entra",
            )
            user_key = directory_natural_key(
                "user",
                user_id,
                namespace="entra",
            )
            provider = FakeProvider(IdentityProviderCollection(
                entries=(
                    DirectoryEntry(user_id, "user", "Cloud User"),
                    DirectoryEntry(app_id, "application", "Example App"),
                ),
                supplemental_evidence=IdentityEvidenceBundle(
                    roles=(
                        RoleEvidence(role_key, "Directory Readers", "role-source"),
                    ),
                    relationships=(
                        IdentityRelationshipEvidence(
                            source_kind=GraphNodeKind.IDENTITY,
                            source_key=user_key,
                            target_kind=GraphNodeKind.PERMISSION,
                            target_key=role_key,
                            relationship="assigned-role",
                            source_id="assignment-source",
                        ),
                    ),
                ),
            ))

            result = collect_authorized_identity_intelligence(
                workspace(root, scope=("tenant.example",)),
                provider,
                IdentityCollectionRequest(
                    engagement_id="eng-identity",
                    source_id="graph-readonly-1",
                    source_type="entra-id",
                    target="tenant.example",
                ),
                now=datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc),
            )

            self.assertEqual(
                {item.identity_type for item in result.evidence.identities},
                {"entra-user", "entra-application"},
            )
            self.assertEqual(len(result.evidence.roles), 1)
            self.assertEqual(len(result.evidence.relationships), 1)

    def test_missing_supplemental_relationship_endpoint_fails_closed(self):
        with tempfile.TemporaryDirectory() as root:
            provider = FakeProvider(IdentityProviderCollection(
                entries=(),
                supplemental_evidence=IdentityEvidenceBundle(
                    roles=(RoleEvidence("entra:role:test", "Role", "source"),),
                    relationships=(
                        IdentityRelationshipEvidence(
                            source_kind=GraphNodeKind.IDENTITY,
                            source_key="entra:user:missing",
                            target_kind=GraphNodeKind.PERMISSION,
                            target_key="entra:role:test",
                            relationship="assigned-role",
                            source_id="source",
                        ),
                    ),
                ),
            ))
            with self.assertRaisesRegex(ValueError, "source is missing"):
                collect_authorized_identity_intelligence(
                    workspace(root, scope=("tenant.example",)),
                    provider,
                    IdentityCollectionRequest(
                        engagement_id="eng-identity",
                        source_id="graph-readonly-1",
                        source_type="entra-id",
                        target="tenant.example",
                    ),
                    now=datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc),
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

    def test_provider_entries_reject_non_group_members_and_duplicate_members(self):
        for kind in ("user", "computer", "service", "application"):
            with self.subTest(kind=kind):
                with self.assertRaises(ValueError):
                    DirectoryEntry("CN=A", kind, "A", ("CN=B",))
        with self.assertRaises(ValueError):
            DirectoryEntry("CN=G", "group", "G", ("CN=A", "CN=A"))
        with self.assertRaises(ValueError):
            DirectoryEntry("CN=X", "unknown", "X")

    def test_provider_entries_reject_unallowlisted_correlation_properties(self):
        with self.assertRaisesRegex(ValueError, "allowlisted"):
            DirectoryEntry(
                "CN=A",
                "computer",
                "A",
                properties=(("password", "secret"),),
            )
        with self.assertRaisesRegex(ValueError, "unique"):
            DirectoryEntry(
                "CN=A",
                "computer",
                "A",
                properties=(
                    ("dns_hostname", "a.example.test"),
                    ("dns_hostname", "b.example.test"),
                ),
            )

    def test_provider_metadata_rejects_invalid_values(self):
        with self.assertRaisesRegex(ValueError, "request_count"):
            IdentityProviderCollection(entries=(), request_count=-1)
        with self.assertRaisesRegex(ValueError, "duration_ms"):
            IdentityProviderCollection(entries=(), duration_ms=-1)
        with self.assertRaisesRegex(ValueError, "limitations"):
            IdentityProviderCollection(entries=(), limitations=("",))


if __name__ == "__main__":
    unittest.main()
