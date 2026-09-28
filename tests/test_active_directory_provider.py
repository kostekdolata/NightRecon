"""Tests for the bounded read-only Active Directory provider."""

from __future__ import annotations

from datetime import datetime, timezone
import tempfile
import unittest

from nightrecon_red_engine.active_directory_provider import (
    AD_GROUP_ATTRIBUTES,
    AD_GROUP_FILTER,
    AD_USER_ATTRIBUTES,
    AD_USER_FILTER,
    ActiveDirectoryIdentityProvider,
    ActiveDirectoryProviderLimits,
    Ldap3ActiveDirectoryTransport,
    LdapSearchPage,
)
from nightrecon_red_engine.identity_collection import (
    IdentityCollectionDenied,
    IdentityCollectionLimits,
    IdentityCollectionRequest,
    collect_authorized_identity_intelligence,
)
from nightrecon_shared_core.contracts import EngagementMetadata
from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy
from nightrecon_shared_core.workspace import LocalWorkspace


class FakeTransport:
    def __init__(self, pages, target="dc.example.test"):
        self._pages = list(pages)
        self._target = target
        self.calls = []
        self.close_calls = 0

    @property
    def target(self):
        return self._target

    def search_page(self, **kwargs):
        self.calls.append(kwargs)
        if not self._pages:
            raise AssertionError("unexpected LDAP page request")
        return self._pages.pop(0)

    def close(self):
        self.close_calls += 1


def request(**kwargs):
    values = {
        "engagement_id": "eng-ad",
        "source_id": "ad-readonly-1",
        "source_type": "active-directory",
        "target": "dc.example.test",
    }
    values.update(kwargs)
    return IdentityCollectionRequest(**values)


def workspace(root, *, scope=("dc.example.test",)):
    item = LocalWorkspace(root)
    item.create_engagement(EngagementMetadata(
        engagement_id="eng-ad",
        name="AD lab",
        created_at="2026-09-28T00:00:00+00:00",
        authorization_reference="approval://eng-ad",
        status="active",
    ))
    item.set_execution_policy(EngagementExecutionPolicy(
        engagement_id="eng-ad",
        scope=scope,
        valid_from="2026-09-28T00:00:00+00:00",
        valid_until="2026-09-29T00:00:00+00:00",
        max_actions=2,
        permitted_capabilities=("identity.collect",),
    ))
    return item


class ActiveDirectoryIdentityProviderTests(unittest.TestCase):
    def test_fixed_plan_collects_users_groups_and_memberships(self):
        transport = FakeTransport((
            LdapSearchPage(entries=(
                {
                    "type": "searchResEntry",
                    "dn": "CN=Alice,DC=example,DC=test",
                    "attributes": {
                        "displayName": "Alice",
                        "sAMAccountName": "alice",
                    },
                },
            )),
            LdapSearchPage(entries=(
                {
                    "type": "searchResEntry",
                    "dn": "CN=Ops,DC=example,DC=test",
                    "attributes": {
                        "cn": "Ops",
                        "member": ["CN=Alice,DC=example,DC=test"],
                    },
                },
            )),
        ))
        provider = ActiveDirectoryIdentityProvider(
            transport=transport,
            base_dn="DC=example,DC=test",
        )

        result = provider.collect(request())

        self.assertFalse(result.truncated)
        self.assertEqual(result.request_count, 2)
        self.assertEqual(len(result.entries), 2)
        by_kind = {entry.kind: entry for entry in result.entries}
        self.assertEqual(by_kind["user"].name, "Alice")
        self.assertEqual(
            by_kind["group"].members,
            ("CN=Alice,DC=example,DC=test",),
        )
        self.assertEqual(
            tuple(call["search_filter"] for call in transport.calls),
            (AD_USER_FILTER, AD_GROUP_FILTER),
        )
        self.assertEqual(
            tuple(call["attributes"] for call in transport.calls),
            (AD_USER_ATTRIBUTES, AD_GROUP_ATTRIBUTES),
        )
        self.assertTrue(all(call["base_dn"] == "DC=example,DC=test"
                            for call in transport.calls))
        self.assertEqual(transport.close_calls, 1)

    def test_identity_page_classifies_users_services_and_computers(self):
        user_dn = "CN=Alice,OU=People,DC=example,DC=test"
        service_dn = "CN=WebSvc,OU=Services,DC=example,DC=test"
        computer_dn = "CN=WS01,OU=Computers,DC=example,DC=test"
        group_dn = "CN=Operators,OU=Groups,DC=example,DC=test"
        transport = FakeTransport((
            LdapSearchPage(entries=(
                {
                    "type": "searchResEntry",
                    "dn": user_dn,
                    "attributes": {
                        "objectClass": ["top", "person", "user"],
                        "displayName": "Alice",
                        "sAMAccountName": "alice",
                    },
                },
                {
                    "type": "searchResEntry",
                    "dn": service_dn,
                    "attributes": {
                        "objectClass": ["top", "person", "user"],
                        "displayName": "Web Service",
                        "sAMAccountName": "websvc",
                        "servicePrincipalName": ["HTTP/app.example.test"],
                    },
                },
                {
                    "type": "searchResEntry",
                    "dn": computer_dn,
                    "attributes": {
                        "objectClass": ["top", "person", "user", "computer"],
                        "sAMAccountName": "WS01$",
                        "dNSHostName": "ws01.example.test",
                        "servicePrincipalName": [
                            "HOST/ws01.example.test",
                            "RestrictedKrbHost/ws01.example.test",
                        ],
                    },
                },
            )),
            LdapSearchPage(entries=(
                {
                    "type": "searchResEntry",
                    "dn": group_dn,
                    "attributes": {
                        "cn": "Operators",
                        "member": [user_dn, service_dn, computer_dn],
                    },
                },
            )),
        ))
        provider = ActiveDirectoryIdentityProvider(
            transport=transport,
            base_dn="DC=example,DC=test",
        )

        result = provider.collect(request())

        self.assertEqual(result.request_count, 2)
        self.assertEqual(
            {entry.kind for entry in result.entries},
            {"user", "service", "computer", "group"},
        )
        by_kind = {entry.kind: entry for entry in result.entries}
        self.assertEqual(by_kind["user"].name, "Alice")
        self.assertEqual(by_kind["service"].name, "Web Service")
        self.assertEqual(by_kind["computer"].name, "ws01.example.test")
        self.assertEqual(
            set(by_kind["group"].members),
            {user_dn, service_dn, computer_dn},
        )
        self.assertFalse(hasattr(by_kind["service"], "service_principal_names"))

    def test_page_ceiling_marks_collection_incomplete_without_overfetch(self):
        transport = FakeTransport((
            LdapSearchPage(
                entries=(
                    {
                        "type": "searchResEntry",
                        "dn": "CN=Alice,DC=example,DC=test",
                        "attributes": {"displayName": "Alice"},
                    },
                ),
                cookie=b"more",
            ),
        ))
        provider = ActiveDirectoryIdentityProvider(
            transport=transport,
            base_dn="DC=example,DC=test",
            limits=ActiveDirectoryProviderLimits(max_pages=1),
        )

        result = provider.collect(request())

        self.assertTrue(result.truncated)
        self.assertEqual(result.request_count, 1)
        self.assertEqual(len(transport.calls), 1)
        self.assertIn("page ceiling", result.limitations[0].lower())
        self.assertEqual(transport.close_calls, 1)

    def test_membership_ceiling_returns_explicit_partial_result(self):
        transport = FakeTransport((
            LdapSearchPage(entries=()),
            LdapSearchPage(entries=(
                {
                    "type": "searchResEntry",
                    "dn": "CN=Ops,DC=example,DC=test",
                    "attributes": {
                        "cn": "Ops",
                        "member": [
                            "CN=Charlie,DC=example,DC=test",
                            "CN=Alice,DC=example,DC=test",
                            "CN=Bob,DC=example,DC=test",
                        ],
                    },
                },
            )),
        ))
        provider = ActiveDirectoryIdentityProvider(
            transport=transport,
            base_dn="DC=example,DC=test",
        )

        result = provider.collect(request(
            limits=IdentityCollectionLimits(max_memberships=2),
        ))

        self.assertTrue(result.truncated)
        group = result.entries[0]
        self.assertEqual(group.kind, "group")
        self.assertEqual(
            group.members,
            (
                "CN=Alice,DC=example,DC=test",
                "CN=Bob,DC=example,DC=test",
            ),
        )
        self.assertIn("membership ceiling", result.limitations[0].lower())

    def test_unfollowed_referrals_are_explicitly_incomplete(self):
        transport = FakeTransport((
            LdapSearchPage(entries=(), referral_count=1),
            LdapSearchPage(entries=()),
        ))
        provider = ActiveDirectoryIdentityProvider(
            transport=transport,
            base_dn="DC=example,DC=test",
        )

        result = provider.collect(request())

        self.assertTrue(result.truncated)
        self.assertTrue(
            any("referrals" in item.lower() for item in result.limitations)
        )
        self.assertEqual(result.request_count, 2)

    def test_ranged_group_membership_is_preserved_but_marked_incomplete(self):
        transport = FakeTransport((
            LdapSearchPage(entries=()),
            LdapSearchPage(entries=(
                {
                    "type": "searchResEntry",
                    "dn": "CN=Large,DC=example,DC=test",
                    "attributes": {
                        "cn": "Large",
                        "member;range=0-1499": [
                            "CN=Alice,DC=example,DC=test",
                            "CN=Bob,DC=example,DC=test",
                        ],
                    },
                },
            )),
        ))
        provider = ActiveDirectoryIdentityProvider(
            transport=transport,
            base_dn="DC=example,DC=test",
        )

        result = provider.collect(request())

        self.assertTrue(result.truncated)
        self.assertEqual(
            result.entries[0].members,
            (
                "CN=Alice,DC=example,DC=test",
                "CN=Bob,DC=example,DC=test",
            ),
        )
        self.assertTrue(
            any("ranged group membership" in item.lower()
                for item in result.limitations)
        )

    def test_wrong_source_or_target_fails_before_transport_call(self):
        for item in (
            request(source_type="entra-id"),
            request(target="other.example.test"),
        ):
            with self.subTest(source_type=item.source_type, target=item.target):
                transport = FakeTransport(())
                provider = ActiveDirectoryIdentityProvider(
                    transport=transport,
                    base_dn="DC=example,DC=test",
                )
                with self.assertRaises(ValueError):
                    provider.collect(item)
                self.assertEqual(transport.calls, [])

    def test_denied_engagement_never_reaches_active_directory_transport(self):
        with tempfile.TemporaryDirectory() as root:
            transport = FakeTransport((
                LdapSearchPage(entries=()),
            ))
            provider = ActiveDirectoryIdentityProvider(
                transport=transport,
                base_dn="DC=example,DC=test",
            )

            with self.assertRaises(IdentityCollectionDenied) as denied:
                collect_authorized_identity_intelligence(
                    workspace(root, scope=("approved.example.test",)),
                    provider,
                    request(),
                    now=datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc),
                )

            self.assertEqual(denied.exception.reason_code, "target_out_of_scope")
            self.assertEqual(transport.calls, [])
            self.assertEqual(transport.close_calls, 0)

    def test_invalid_response_fails_closed_and_transport_is_closed(self):
        transport = FakeTransport((
            LdapSearchPage(entries=(
                {
                    "type": "searchResEntry",
                    "dn": "CN=Alice,DC=example,DC=test",
                    "attributes": "not-a-mapping",
                },
            )),
        ))
        provider = ActiveDirectoryIdentityProvider(
            transport=transport,
            base_dn="DC=example,DC=test",
        )

        with self.assertRaisesRegex(ValueError, "attributes"):
            provider.collect(request())

        self.assertEqual(transport.close_calls, 1)

    def test_transport_rejects_plaintext_and_arbitrary_queries(self):
        with self.assertRaisesRegex(ValueError, "ldaps or starttls"):
            Ldap3ActiveDirectoryTransport(
                host="dc.example.test",
                bind_username="EXAMPLE\\reader",
                secret_resolver=lambda: "secret",
                mode="plaintext",
            )

        transport = Ldap3ActiveDirectoryTransport(
            host="dc.example.test",
            bind_username="EXAMPLE\\reader",
            secret_resolver=lambda: "secret",
        )
        with self.assertRaisesRegex(ValueError, "fixed AD collection plan"):
            transport.search_page(
                base_dn="DC=example,DC=test",
                search_filter="(objectClass=*)",
                attributes=("distinguishedName",),
                page_size=100,
                page_cookie=None,
                time_limit_seconds=5,
            )
        self.assertNotIn("secret", repr(transport))


if __name__ == "__main__":
    unittest.main()
