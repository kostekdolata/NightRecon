"""Deterministic no-network Active Directory benchmark-lab smoke."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import tempfile

from nightrecon_red_engine.active_directory_provider import (
    ActiveDirectoryIdentityProvider,
    LdapSearchPage,
)
from nightrecon_red_engine.graph_identity_evidence import (
    GroupMembershipEvidence,
    IdentityEvidence,
    IdentityEvidenceBundle,
    IdentityRelationshipEvidence,
    RoleEvidence,
)
from nightrecon_red_engine.graph_models import GraphNodeKind
from nightrecon_red_engine.identity_benchmark import benchmark_identity_collection
from nightrecon_red_engine.identity_collection import (
    IdentityCollectionRequest,
    collect_authorized_identity_intelligence,
)
from nightrecon_red_engine.red_directory_import import (
    directory_natural_key,
    import_directory_snapshot,
)
from nightrecon_shared_core.contracts import EngagementMetadata
from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy
from nightrecon_shared_core.workspace import LocalWorkspace


BASE_DN = "DC=example,DC=test"
USER_DN = "CN=Alice,DC=example,DC=test"
SERVICE_DN = "CN=WebSvc,DC=example,DC=test"
COMPUTER_DN = "CN=WS01,DC=example,DC=test"
DOMAIN_USERS_DN = "CN=Domain Users,CN=Users,DC=example,DC=test"
DOMAIN_ADMINS_DN = "CN=Domain Admins,CN=Users,DC=example,DC=test"
PARTNER_DOMAIN = "partner.test"
DOMAIN_SID = "S-1-5-21-100-200-300"


class FixtureTransport:
    target = "dc.example.test"

    def __init__(self) -> None:
        self.calls = 0
        self.closed = False
        self._pages = [
            LdapSearchPage(entries=(
                {
                    "type": "searchResEntry",
                    "dn": USER_DN,
                    "attributes": {
                        "objectClass": ["top", "person", "user"],
                        "displayName": "Alice",
                        "sAMAccountName": "alice",
                        "objectSid": f"{DOMAIN_SID}-1100",
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
                        "objectSid": f"{DOMAIN_SID}-1200",
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
                        "objectSid": f"{DOMAIN_SID}-1300",
                        "primaryGroupID": 513,
                        "servicePrincipalName": ["HOST/ws01.example.test"],
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
                        "objectSid": f"{DOMAIN_SID}-513",
                        "member": [],
                    },
                },
                {
                    "type": "searchResEntry",
                    "dn": DOMAIN_ADMINS_DN,
                    "attributes": {
                        "objectClass": ["top", "group"],
                        "cn": "Domain Admins",
                        "objectSid": f"{DOMAIN_SID}-512",
                        "managedBy": USER_DN,
                        "member": [SERVICE_DN],
                    },
                },
                {
                    "type": "searchResEntry",
                    "dn": "CN=partner.test,CN=System,DC=example,DC=test",
                    "attributes": {
                        "objectClass": ["top", "trustedDomain"],
                        "trustPartner": PARTNER_DOMAIN,
                        "trustDirection": 3,
                        "trustType": 2,
                        "trustAttributes": 8,
                    },
                },
            )),
        ]

    def search_page(self, **kwargs):
        self.calls += 1
        return self._pages.pop(0)

    def close(self) -> None:
        self.closed = True


def workspace(root: str) -> LocalWorkspace:
    item = LocalWorkspace(root)
    item.create_engagement(EngagementMetadata(
        engagement_id="eng-ad-benchmark",
        name="AD benchmark fixture",
        created_at="2026-09-29T00:00:00+00:00",
        authorization_reference="fixture://authorized",
        status="active",
    ))
    item.set_execution_policy(EngagementExecutionPolicy(
        engagement_id="eng-ad-benchmark",
        scope=("dc.example.test",),
        valid_from="2026-09-29T00:00:00+00:00",
        valid_until="2026-09-30T00:00:00+00:00",
        max_actions=1,
        permitted_capabilities=("identity.collect",),
    ))
    return item


def expected_evidence() -> IdentityEvidenceBundle:
    imported = import_directory_snapshot(
        (
            '{"schema_version":1,"entries":['
            f'{{"dn":"{USER_DN}","kind":"user","name":"Alice"}},'
            f'{{"dn":"{SERVICE_DN}","kind":"service","name":"Web Service"}},'
            f'{{"dn":"{COMPUTER_DN}","kind":"computer","name":"ws01.example.test"}},'
            f'{{"dn":"{DOMAIN_USERS_DN}","kind":"group","name":"Domain Users","members":[]}},'
            f'{{"dn":"{DOMAIN_ADMINS_DN}","kind":"group","name":"Domain Admins",'
            f'"members":["{SERVICE_DN}"]}}'
            ']}'
        ).encode("utf-8"),
        source_id="benchmark-expected",
    )

    user_key = directory_natural_key("user", USER_DN, namespace="ad")
    service_key = directory_natural_key("service", SERVICE_DN, namespace="ad")
    computer_key = directory_natural_key("computer", COMPUTER_DN, namespace="ad")
    domain_users_key = directory_natural_key(
        "group", DOMAIN_USERS_DN, namespace="ad"
    )
    domain_admins_key = directory_natural_key(
        "group", DOMAIN_ADMINS_DN, namespace="ad"
    )
    role_key = directory_natural_key(
        "role",
        f"privileged-group:{DOMAIN_SID}-512",
        namespace="ad",
    )
    current_domain_key = directory_natural_key("domain", BASE_DN, namespace="ad")
    partner_domain_key = directory_natural_key(
        "domain", PARTNER_DOMAIN, namespace="ad"
    )

    return IdentityEvidenceBundle(
        identities=imported.evidence.identities + (
            IdentityEvidence(
                current_domain_key,
                BASE_DN,
                "benchmark-domain",
                identity_type="ad-domain",
            ),
            IdentityEvidence(
                partner_domain_key,
                PARTNER_DOMAIN,
                "benchmark-trust",
                identity_type="ad-domain",
            ),
        ),
        groups=imported.evidence.groups,
        memberships=imported.evidence.memberships + (
            GroupMembershipEvidence(
                GraphNodeKind.IDENTITY,
                user_key,
                domain_users_key,
                "benchmark-primary-group",
            ),
            GroupMembershipEvidence(
                GraphNodeKind.IDENTITY,
                service_key,
                domain_users_key,
                "benchmark-primary-group",
            ),
            GroupMembershipEvidence(
                GraphNodeKind.IDENTITY,
                computer_key,
                domain_users_key,
                "benchmark-primary-group",
            ),
        ),
        roles=(
            RoleEvidence(
                role_key,
                "Domain Admins",
                "benchmark-privileged-group",
                properties=(
                    ("category", "well-known-ad-privileged-group"),
                    ("rid", "512"),
                ),
            ),
        ),
        relationships=(
            IdentityRelationshipEvidence(
                GraphNodeKind.GROUP,
                domain_admins_key,
                GraphNodeKind.PERMISSION,
                role_key,
                "assigned-role",
                "benchmark-privileged-group",
                properties=(("rid", "512"),),
            ),
            IdentityRelationshipEvidence(
                GraphNodeKind.IDENTITY,
                user_key,
                GraphNodeKind.GROUP,
                domain_admins_key,
                "manages",
                "benchmark-managed-by",
            ),
            IdentityRelationshipEvidence(
                GraphNodeKind.IDENTITY,
                service_key,
                GraphNodeKind.IDENTITY,
                computer_key,
                "delegates-to",
                "benchmark-delegation",
            ),
            IdentityRelationshipEvidence(
                GraphNodeKind.IDENTITY,
                current_domain_key,
                GraphNodeKind.IDENTITY,
                partner_domain_key,
                "domain-trust",
                "benchmark-domain-trust",
                properties=(
                    ("trust_direction", "3"),
                    ("trust_type", "2"),
                    ("trust_attributes", "8"),
                ),
            ),
        ),
    )


def main() -> None:
    with tempfile.TemporaryDirectory() as root:
        transport = FixtureTransport()
        provider = ActiveDirectoryIdentityProvider(
            transport=transport,
            base_dn=BASE_DN,
            clock=lambda: 100.0,
        )
        collected = collect_authorized_identity_intelligence(
            workspace(root),
            provider,
            IdentityCollectionRequest(
                engagement_id="eng-ad-benchmark",
                source_id="benchmark-observed",
                source_type="active-directory",
                target="dc.example.test",
            ),
            now=datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc),
        )

    benchmark = benchmark_identity_collection(collected, expected_evidence())
    record = benchmark.to_dict()

    assert transport.calls == 2
    assert transport.closed
    assert benchmark.provider_requests == 2
    assert benchmark.provider_duration_ms == 0
    assert benchmark.expected_coverage_complete
    assert not benchmark.unexpected_evidence_present
    assert benchmark.expected_identities == 5
    assert benchmark.discovered_expected_identities == 5
    assert benchmark.expected_groups == 2
    assert benchmark.expected_memberships == 4
    assert benchmark.expected_roles == 1
    assert benchmark.expected_relationships == 4
    assert benchmark.missed_identities == 0
    assert benchmark.missed_groups == 0
    assert benchmark.missed_memberships == 0
    assert benchmark.missed_roles == 0
    assert benchmark.missed_relationships == 0
    assert benchmark.invented_relationships == 0
    assert len(benchmark.graph_sha256) == 64
    assert len(benchmark.benchmark_sha256) == 64

    rendered = json.dumps(record, sort_keys=True)
    for sensitive in (
        "Alice",
        "Web Service",
        "ws01.example.test",
        "Domain Users",
        "Domain Admins",
        PARTNER_DOMAIN,
        USER_DN,
        SERVICE_DN,
        COMPUTER_DN,
        DOMAIN_USERS_DN,
        DOMAIN_ADMINS_DN,
        BASE_DN,
    ):
        assert sensitive not in rendered

    print(rendered)


if __name__ == "__main__":
    main()
