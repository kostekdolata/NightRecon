"""Tests for bounded Active Directory privilege, delegation, and trust evidence."""

from __future__ import annotations

from datetime import datetime, timezone
import tempfile
import unittest

from nightrecon_red_engine.active_directory_provider import (
    ActiveDirectoryIdentityProvider,
    ActiveDirectoryProviderLimits,
    LdapSearchPage,
)
from nightrecon_red_engine.graph_models import GraphNodeKind
from nightrecon_red_engine.identity_collection import (
    IdentityCollectionRequest,
    collect_authorized_identity_intelligence,
)
from nightrecon_shared_core.contracts import EngagementMetadata
from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy
from nightrecon_shared_core.workspace import LocalWorkspace


BASE_DN = "DC=example,DC=test"
TARGET = "dc.example.test"
USER_DN = "CN=Alice,OU=People,DC=example,DC=test"
SERVICE_DN = "CN=WebSvc,OU=Services,DC=example,DC=test"
COMPUTER_DN = "CN=WS01,OU=Computers,DC=example,DC=test"
DOMAIN_USERS_DN = "CN=Domain Users,CN=Users,DC=example,DC=test"
DOMAIN_ADMINS_DN = "CN=Domain Admins,CN=Users,DC=example,DC=test"


class FakeTransport:
    target = TARGET

    def __init__(self, pages):
        self._pages = list(pages)
        self.calls = []
        self.close_calls = 0

    def search_page(self, **kwargs):
        self.calls.append(kwargs)
        if not self._pages:
            raise AssertionError("unexpected LDAP page request")
        return self._pages.pop(0)

    def close(self):
        self.close_calls += 1


def request():
    return IdentityCollectionRequest(
        engagement_id="eng-ad-rel",
        source_id="ad-rel-1",
        source_type="active-directory",
        target=TARGET,
    )


def workspace(root: str) -> LocalWorkspace:
    item = LocalWorkspace(root)
    item.create_engagement(EngagementMetadata(
        engagement_id="eng-ad-rel",
        name="AD relationship lab",
        created_at="2026-09-29T00:00:00+00:00",
        authorization_reference="fixture://authorized",
        status="active",
    ))
    item.set_execution_policy(EngagementExecutionPolicy(
        engagement_id="eng-ad-rel",
        scope=(TARGET,),
        valid_from="2026-09-29T00:00:00+00:00",
        valid_until="2026-09-30T00:00:00+00:00",
        max_actions=1,
        permitted_capabilities=("identity.collect",),
    ))
    return item


def relationship_pages():
    return (
        LdapSearchPage(entries=(
            {
                "type": "searchResEntry",
                "dn": USER_DN,
                "attributes": {
                    "objectClass": ["top", "person", "user"],
                    "displayName": "Alice",
                    "sAMAccountName": "alice",
                    "objectSid": "S-1-5-21-100-200-300-1100",
                    "primaryGroupID": 513,
                },
            },
            {
                "type": "searchResEntry",
                "dn": SERVICE_DN,
                "attributes": {
                    "objectClass": ["top", "person", "user"],
                    "displayName": "Web Service",
                    "sAMAccountName": "websvc",
                    "objectSid": "S-1-5-21-100-200-300-1200",
                    "primaryGroupID": 513,
                    "servicePrincipalName": ["HTTP/app.example.test"],
                    "msDS-AllowedToDelegateTo": ["HOST/ws01.example.test"],
                },
            },
            {
                "type": "searchResEntry",
                "dn": COMPUTER_DN,
                "attributes": {
                    "objectClass": ["top", "person", "user", "computer"],
                    "sAMAccountName": "WS01$",
                    "dNSHostName": "ws01.example.test",
                    "objectSid": "S-1-5-21-100-200-300-1300",
                    "primaryGroupID": 513,
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
                "dn": DOMAIN_USERS_DN,
                "attributes": {
                    "objectClass": ["top", "group"],
                    "cn": "Domain Users",
                    "objectSid": "S-1-5-21-100-200-300-513",
                    "member": [],
                },
            },
            {
                "type": "searchResEntry",
                "dn": DOMAIN_ADMINS_DN,
                "attributes": {
                    "objectClass": ["top", "group"],
                    "cn": "Domain Admins",
                    "objectSid": "S-1-5-21-100-200-300-512",
                    "managedBy": USER_DN,
                    "member": [SERVICE_DN],
                },
            },
            {
                "type": "searchResEntry",
                "dn": "CN=partner.test,CN=System,DC=example,DC=test",
                "attributes": {
                    "objectClass": ["top", "trustedDomain"],
                    "trustPartner": "partner.test",
                    "flatName": "PARTNER",
                    "trustDirection": 3,
                    "trustType": 2,
                    "trustAttributes": 8,
                },
            },
        )),
    )


class ActiveDirectoryRelationshipTests(unittest.TestCase):
    def test_collects_primary_group_management_delegation_privilege_and_trust(self):
        transport = FakeTransport(relationship_pages())
        provider = ActiveDirectoryIdentityProvider(
            transport=transport,
            base_dn=BASE_DN,
            clock=lambda: 100.0,
        )

        result = provider.collect(request())

        self.assertEqual(result.request_count, 2)
        self.assertEqual(transport.close_calls, 1)
        supplemental = result.supplemental_evidence
        self.assertEqual(len(supplemental.identities), 2)
        self.assertEqual(
            {item.identity_type for item in supplemental.identities},
            {"ad-domain"},
        )
        self.assertEqual(len(supplemental.roles), 1)
        self.assertEqual(supplemental.roles[0].label, "Domain Admins")

        # Alice, WebSvc and WS01 all use Domain Users as primary group.
        self.assertEqual(len(supplemental.memberships), 3)
        self.assertTrue(all(
            item.member_kind is GraphNodeKind.IDENTITY
            for item in supplemental.memberships
        ))

        relationships = supplemental.relationships
        self.assertEqual(
            [item.relationship for item in relationships].count("assigned-role"),
            1,
        )
        self.assertEqual(
            [item.relationship for item in relationships].count("manages"),
            1,
        )
        self.assertEqual(
            [item.relationship for item in relationships].count("delegates-to"),
            1,
        )
        self.assertEqual(
            [item.relationship for item in relationships].count("domain-trust"),
            1,
        )
        trust = next(
            item for item in relationships
            if item.relationship == "domain-trust"
        )
        self.assertEqual(
            dict(trust.properties),
            {
                "trust_direction": "3",
                "trust_type": "2",
                "trust_attributes": "8",
            },
        )
        self.assertFalse(result.truncated)

    def test_authorized_collection_merges_relationships_into_graph_evidence(self):
        with tempfile.TemporaryDirectory() as root:
            result = collect_authorized_identity_intelligence(
                workspace(root),
                ActiveDirectoryIdentityProvider(
                    transport=FakeTransport(relationship_pages()),
                    base_dn=BASE_DN,
                    clock=lambda: 100.0,
                ),
                request(),
                now=datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc),
            )

        self.assertEqual(
            {item.identity_type for item in result.evidence.identities},
            {"ad-user", "ad-service", "ad-computer", "ad-domain"},
        )
        self.assertEqual(len(result.evidence.groups), 2)
        # One explicit Domain Admins membership + three primary-group memberships.
        self.assertEqual(len(result.evidence.memberships), 4)
        self.assertEqual(len(result.evidence.roles), 1)
        self.assertEqual(len(result.evidence.relationships), 4)

    def test_missing_managed_by_and_delegation_targets_are_explicitly_incomplete(self):
        pages = (
            LdapSearchPage(entries=(
                {
                    "type": "searchResEntry",
                    "dn": SERVICE_DN,
                    "attributes": {
                        "objectClass": ["top", "person", "user"],
                        "displayName": "Web Service",
                        "servicePrincipalName": ["HTTP/app.example.test"],
                        "msDS-AllowedToDelegateTo": ["HOST/missing.example.test"],
                    },
                },
            )),
            LdapSearchPage(entries=(
                {
                    "type": "searchResEntry",
                    "dn": DOMAIN_ADMINS_DN,
                    "attributes": {
                        "objectClass": ["top", "group"],
                        "cn": "Domain Admins",
                        "objectSid": "S-1-5-21-100-200-300-512",
                        "managedBy": "CN=Missing,DC=example,DC=test",
                    },
                },
            )),
        )
        result = ActiveDirectoryIdentityProvider(
            transport=FakeTransport(pages),
            base_dn=BASE_DN,
        ).collect(request())

        self.assertTrue(result.truncated)
        self.assertTrue(any(
            "managedby" in item.lower() for item in result.limitations
        ))
        self.assertTrue(any(
            "constrained-delegation target" in item.lower()
            for item in result.limitations
        ))
        self.assertEqual(
            [item.relationship for item in result.supplemental_evidence.relationships],
            ["assigned-role"],
        )

    def test_relationship_ceiling_is_hard(self):
        provider = ActiveDirectoryIdentityProvider(
            transport=FakeTransport(relationship_pages()),
            base_dn=BASE_DN,
            limits=ActiveDirectoryProviderLimits(max_relationships=2),
        )

        result = provider.collect(request())

        self.assertTrue(result.truncated)
        self.assertLessEqual(
            len(result.supplemental_evidence.relationships),
            2,
        )
        self.assertTrue(any(
            "relationship ceiling" in item.lower()
            for item in result.limitations
        ))


if __name__ == "__main__":
    unittest.main()
