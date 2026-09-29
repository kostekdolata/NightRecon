"""Deterministic no-network Microsoft Entra benchmark-lab smoke."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import tempfile

from nightrecon_red_engine.entra_provider import (
    GRAPH_GROUPS_PATH,
    GRAPH_SERVICE_PRINCIPALS_PATH,
    GRAPH_USERS_PATH,
    EntraIdentityProvider,
    GraphPage,
)
from nightrecon_red_engine.identity_benchmark import benchmark_identity_collection
from nightrecon_red_engine.identity_collection import (
    IdentityCollectionRequest,
    collect_authorized_identity_intelligence,
)
from nightrecon_red_engine.red_directory_import import import_directory_snapshot
from nightrecon_shared_core.contracts import EngagementMetadata
from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy
from nightrecon_shared_core.workspace import LocalWorkspace


TENANT = "11111111-2222-3333-4444-555555555555"
USER_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
GROUP_ID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
SERVICE_ID = "cccccccc-cccc-cccc-cccc-cccccccccccc"


class FixtureTransport:
    def __init__(self) -> None:
        self.calls = 0
        self.closed = False
        members_path = (
            f"/v1.0/groups/{GROUP_ID}/members"
            "?$select=id,displayName,userPrincipalName,appId&$top=100"
        )
        self._pages = {
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
                    "displayName": "Cloud Operators",
                },
            )),
            GRAPH_SERVICE_PRINCIPALS_PATH: GraphPage(items=(
                {
                    "id": SERVICE_ID,
                    "displayName": "Example Service Principal",
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
                    "displayName": "Example Service Principal",
                    "@odata.type": "#microsoft.graph.servicePrincipal",
                },
            )),
        }

    def get_page(self, path_or_url):
        self.calls += 1
        return self._pages[path_or_url]

    def close(self) -> None:
        self.closed = True


def workspace(root: str) -> LocalWorkspace:
    item = LocalWorkspace(root)
    item.create_engagement(EngagementMetadata(
        engagement_id="eng-entra-benchmark",
        name="Entra benchmark fixture",
        created_at="2026-09-29T00:00:00+00:00",
        authorization_reference="fixture://authorized",
        status="active",
    ))
    item.set_execution_policy(EngagementExecutionPolicy(
        engagement_id="eng-entra-benchmark",
        scope=(TENANT,),
        valid_from="2026-09-29T00:00:00+00:00",
        valid_until="2026-09-30T00:00:00+00:00",
        max_actions=1,
        permitted_capabilities=("identity.collect",),
    ))
    return item


def main() -> None:
    expected = import_directory_snapshot(
        (
            '{"schema_version":1,"entries":['
            f'{{"dn":"{USER_ID}","kind":"user","name":"Cloud User"}},'
            f'{{"dn":"{SERVICE_ID}","kind":"service","name":"Example Service Principal"}},'
            f'{{"dn":"{GROUP_ID}","kind":"group","name":"Cloud Operators",'
            f'"members":["{USER_ID}","{SERVICE_ID}"]}}'
            ']}'
        ).encode("utf-8"),
        source_id="entra-benchmark-expected",
        namespace="entra",
    )

    with tempfile.TemporaryDirectory() as root:
        transport = FixtureTransport()
        provider = EntraIdentityProvider(
            transport=transport,
            tenant_id=TENANT,
            clock=lambda: 100.0,
        )
        collected = collect_authorized_identity_intelligence(
            workspace(root),
            provider,
            IdentityCollectionRequest(
                engagement_id="eng-entra-benchmark",
                source_id="entra-benchmark-observed",
                source_type="entra-id",
                target=TENANT,
            ),
            now=datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc),
        )

    benchmark = benchmark_identity_collection(collected, expected.evidence)
    record = benchmark.to_dict()

    assert transport.calls == 4
    assert transport.closed
    assert benchmark.provider_requests == 4
    assert benchmark.provider_duration_ms == 0
    assert benchmark.expected_coverage_complete
    assert not benchmark.unexpected_evidence_present
    assert benchmark.expected_identities == 2
    assert benchmark.discovered_expected_identities == 2
    assert benchmark.expected_groups == 1
    assert benchmark.expected_memberships == 2
    assert benchmark.missed_identities == 0
    assert benchmark.missed_groups == 0
    assert benchmark.missed_memberships == 0
    assert benchmark.invented_memberships == 0
    assert benchmark.truncated
    assert any(
        "service-principal group membership" in item.lower()
        for item in benchmark.limitations
    )
    assert len(benchmark.graph_sha256) == 64
    assert len(benchmark.benchmark_sha256) == 64

    rendered = json.dumps(record, sort_keys=True)
    assert "Cloud User" not in rendered
    assert "Example Service Principal" not in rendered
    assert "Cloud Operators" not in rendered
    assert USER_ID not in rendered
    assert SERVICE_ID not in rendered
    assert GROUP_ID not in rendered

    print(rendered)


if __name__ == "__main__":
    main()
