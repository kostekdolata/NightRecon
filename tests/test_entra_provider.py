"""Tests for the bounded read-only Microsoft Entra provider."""

from __future__ import annotations

from datetime import datetime, timezone
import io
import tempfile
import unittest
from urllib.error import HTTPError

from nightrecon_red_engine.entra_provider import (
    GRAPH_GROUPS_PATH,
    GRAPH_SERVICE_PRINCIPALS_PATH,
    GRAPH_USERS_PATH,
    EntraIdentityProvider,
    EntraProviderLimits,
    GraphPage,
    MicrosoftGraphTransport,
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


TENANT = "11111111-2222-3333-4444-555555555555"
USER_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
GROUP_ID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
SERVICE_ID = "cccccccc-cccc-cccc-cccc-cccccccccccc"


class FakeGraphTransport:
    def __init__(self, pages):
        self.pages = dict(pages)
        self.calls = []
        self.close_calls = 0

    def get_page(self, path_or_url):
        self.calls.append(path_or_url)
        if path_or_url not in self.pages:
            raise AssertionError(f"unexpected Graph request: {path_or_url}")
        return self.pages[path_or_url]

    def close(self):
        self.close_calls += 1


def request(**kwargs):
    values = {
        "engagement_id": "eng-entra",
        "source_id": "graph-readonly-1",
        "source_type": "entra-id",
        "target": TENANT,
    }
    values.update(kwargs)
    return IdentityCollectionRequest(**values)


def workspace(root, *, scope=(TENANT,)):
    item = LocalWorkspace(root)
    item.create_engagement(EngagementMetadata(
        engagement_id="eng-entra",
        name="Entra lab",
        created_at="2026-09-29T00:00:00+00:00",
        authorization_reference="approval://eng-entra",
        status="active",
    ))
    item.set_execution_policy(EngagementExecutionPolicy(
        engagement_id="eng-entra",
        scope=scope,
        valid_from="2026-09-29T00:00:00+00:00",
        valid_until="2026-09-30T00:00:00+00:00",
        max_actions=2,
        permitted_capabilities=("identity.collect",),
    ))
    return item


def base_pages():
    members_path = (
        f"/v1.0/groups/{GROUP_ID}/members"
        "?$select=id,displayName,userPrincipalName,appId&$top=100"
    )
    return {
        GRAPH_USERS_PATH: GraphPage(items=(
            {
                "id": USER_ID,
                "displayName": "Cloud User",
                "userPrincipalName": "cloud.user@example.test",
            },
        )),
        GRAPH_GROUPS_PATH: GraphPage(items=(
            {
                "id": GROUP_ID,
                "displayName": "Operators",
            },
        )),
        GRAPH_SERVICE_PRINCIPALS_PATH: GraphPage(items=(
            {
                "id": SERVICE_ID,
                "displayName": "Example App",
                "appId": "dddddddd-dddd-dddd-dddd-dddddddddddd",
            },
        )),
        members_path: GraphPage(items=(
            {
                "id": USER_ID,
                "displayName": "Cloud User",
                "@odata.type": "#microsoft.graph.user",
            },
            {
                "id": SERVICE_ID,
                "displayName": "Example App",
                "@odata.type": "#microsoft.graph.servicePrincipal",
            },
        )),
    }


class EntraIdentityProviderTests(unittest.TestCase):
    def test_fixed_plan_collects_users_groups_services_and_memberships(self):
        transport = FakeGraphTransport(base_pages())
        provider = EntraIdentityProvider(
            transport=transport,
            tenant_id=TENANT,
            clock=lambda: 100.0,
        )

        result = provider.collect(request())

        self.assertEqual(result.request_count, 4)
        self.assertEqual(result.duration_ms, 0)
        self.assertEqual(
            {entry.kind for entry in result.entries},
            {"user", "service", "group"},
        )
        by_kind = {entry.kind: entry for entry in result.entries}
        self.assertEqual(by_kind["user"].distinguished_name, USER_ID)
        self.assertEqual(by_kind["service"].distinguished_name, SERVICE_ID)
        self.assertEqual(
            set(by_kind["group"].members),
            {USER_ID, SERVICE_ID},
        )
        self.assertEqual(
            transport.calls[:3],
            [
                GRAPH_USERS_PATH,
                GRAPH_GROUPS_PATH,
                GRAPH_SERVICE_PRINCIPALS_PATH,
            ],
        )
        self.assertEqual(transport.close_calls, 1)
        self.assertTrue(result.truncated)
        self.assertTrue(
            any("service-principal group membership" in item.lower()
                for item in result.limitations)
        )

    def test_tenant_mismatch_fails_before_graph_call(self):
        transport = FakeGraphTransport({})
        provider = EntraIdentityProvider(
            transport=transport,
            tenant_id=TENANT,
        )

        with self.assertRaisesRegex(ValueError, "configured tenant"):
            provider.collect(request(target="other-tenant"))

        self.assertEqual(transport.calls, [])
        self.assertEqual(transport.close_calls, 0)

    def test_denied_engagement_never_reaches_graph_transport(self):
        transport = FakeGraphTransport({})
        provider = EntraIdentityProvider(
            transport=transport,
            tenant_id=TENANT,
        )

        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(IdentityCollectionDenied) as denied:
                collect_authorized_identity_intelligence(
                    workspace(root, scope=("approved-tenant",)),
                    provider,
                    request(),
                    now=datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc),
                )

        self.assertEqual(denied.exception.reason_code, "target_out_of_scope")
        self.assertEqual(transport.calls, [])
        self.assertEqual(transport.close_calls, 0)

    def test_request_ceiling_stops_before_additional_collections(self):
        transport = FakeGraphTransport({
            GRAPH_USERS_PATH: GraphPage(items=(
                {"id": USER_ID, "displayName": "Cloud User"},
            )),
        })
        provider = EntraIdentityProvider(
            transport=transport,
            tenant_id=TENANT,
            limits=EntraProviderLimits(max_requests=1),
        )

        result = provider.collect(request())

        self.assertEqual(result.request_count, 1)
        self.assertEqual(len(result.entries), 1)
        self.assertTrue(result.truncated)
        self.assertTrue(
            any("request ceiling" in item.lower() for item in result.limitations)
        )
        self.assertEqual(transport.calls, [GRAPH_USERS_PATH])

    def test_entry_ceiling_prevents_unbounded_collection(self):
        transport = FakeGraphTransport({
            GRAPH_USERS_PATH: GraphPage(items=(
                {"id": USER_ID, "displayName": "Cloud User"},
                {
                    "id": "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
                    "displayName": "Second User",
                },
            )),
        })
        provider = EntraIdentityProvider(
            transport=transport,
            tenant_id=TENANT,
        )

        result = provider.collect(request(
            limits=IdentityCollectionLimits(max_entries=1),
        ))

        self.assertEqual(len(result.entries), 1)
        self.assertTrue(result.truncated)
        self.assertTrue(
            any("entry ceiling" in item.lower() for item in result.limitations)
        )

    def test_unsupported_member_type_is_omitted_and_reported(self):
        pages = base_pages()
        members_path = next(
            path for path in pages if "/members?" in path
        )
        pages[members_path] = GraphPage(items=(
            {
                "id": "ffffffff-ffff-ffff-ffff-ffffffffffff",
                "displayName": "Device",
                "@odata.type": "#microsoft.graph.device",
            },
        ))
        transport = FakeGraphTransport(pages)
        provider = EntraIdentityProvider(
            transport=transport,
            tenant_id=TENANT,
        )

        result = provider.collect(request())

        group = next(entry for entry in result.entries if entry.kind == "group")
        self.assertEqual(group.members, ())
        self.assertTrue(result.truncated)
        self.assertTrue(
            any("unsupported group member type" in item.lower()
                for item in result.limitations)
        )

    def test_invalid_graph_item_fails_closed_and_transport_closes(self):
        pages = base_pages()
        pages[GRAPH_USERS_PATH] = GraphPage(items=(
            {"displayName": "Missing id"},
        ))
        transport = FakeGraphTransport(pages)
        provider = EntraIdentityProvider(
            transport=transport,
            tenant_id=TENANT,
        )

        with self.assertRaisesRegex(ValueError, "object id"):
            provider.collect(request())

        self.assertEqual(transport.close_calls, 1)

    def test_transport_rejects_arbitrary_hosts_versions_and_fields_before_token(self):
        resolved = []

        def token():
            resolved.append(True)
            return "secret-token"

        transport = MicrosoftGraphTransport(access_token_resolver=token)
        for url in (
            "http://graph.microsoft.com/v1.0/users"
            "?$select=id,displayName,userPrincipalName&$top=100",
            "https://example.test/v1.0/users"
            "?$select=id,displayName,userPrincipalName&$top=100",
            "https://graph.microsoft.com/beta/users"
            "?$select=id,displayName,userPrincipalName&$top=100",
            "https://graph.microsoft.com/v1.0/users"
            "?$select=id,passwordProfile&$top=100",
            "https://graph.microsoft.com/v1.0/users"
            "?$select=id,displayName,userPrincipalName&$top=100&$filter=accountEnabled",
        ):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    transport.get_page(url)

        self.assertEqual(resolved, [])
        self.assertNotIn("secret-token", repr(transport))

    def test_token_resolution_failure_is_secret_free(self):
        def resolver():
            raise RuntimeError("secret-token-provider-detail")

        transport = MicrosoftGraphTransport(access_token_resolver=resolver)

        with self.assertRaises(LookupError) as error:
            transport.get_page(GRAPH_USERS_PATH)

        self.assertEqual(
            str(error.exception),
            "Microsoft Graph access token could not be resolved",
        )
        self.assertNotIn("secret-token-provider-detail", str(error.exception))

    def test_redirect_response_is_not_followed_or_exposed(self):
        class RedirectingOpener:
            def __init__(self):
                self.calls = 0

            def open(self, request, timeout):
                self.calls += 1
                raise HTTPError(
                    request.full_url,
                    302,
                    "Found",
                    {"Location": "https://evil.example/steal"},
                    io.BytesIO(b""),
                )

        opener = RedirectingOpener()
        transport = MicrosoftGraphTransport(
            access_token_resolver=lambda: "secret-token",
        )
        transport._opener = opener

        with self.assertRaises(RuntimeError) as error:
            transport.get_page(GRAPH_USERS_PATH)

        self.assertEqual(opener.calls, 1)
        self.assertEqual(
            str(error.exception),
            "Microsoft Graph read-only request failed with HTTP 302",
        )
        self.assertNotIn("secret-token", str(error.exception))
        self.assertNotIn("evil.example", str(error.exception))

    def test_graph_page_rejects_scope_escape_next_link(self):
        with self.assertRaisesRegex(ValueError, "graph.microsoft.com"):
            GraphPage(
                items=(),
                next_link=(
                    "https://evil.example/v1.0/users"
                    "?$select=id,displayName,userPrincipalName&$top=100"
                    "&$skiptoken=abc"
                ),
            )


if __name__ == "__main__":
    unittest.main()
