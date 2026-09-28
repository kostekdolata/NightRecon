"""Deterministic no-network Active Directory benchmark-lab smoke."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import tempfile

from nightrecon_red_engine.active_directory_provider import (
    ActiveDirectoryIdentityProvider,
    LdapSearchPage,
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


USER_DN = "CN=Alice,DC=example,DC=test"
GROUP_DN = "CN=Ops,DC=example,DC=test"


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
                        "displayName": "Alice",
                        "sAMAccountName": "alice",
                    },
                },
            )),
            LdapSearchPage(entries=(
                {
                    "type": "searchResEntry",
                    "dn": GROUP_DN,
                    "attributes": {
                        "cn": "Ops",
                        "member": [USER_DN],
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
        created_at="2026-09-28T00:00:00+00:00",
        authorization_reference="fixture://authorized",
        status="active",
    ))
    item.set_execution_policy(EngagementExecutionPolicy(
        engagement_id="eng-ad-benchmark",
        scope=("dc.example.test",),
        valid_from="2026-09-28T00:00:00+00:00",
        valid_until="2026-09-29T00:00:00+00:00",
        max_actions=1,
        permitted_capabilities=("identity.collect",),
    ))
    return item


def main() -> None:
    expected = import_directory_snapshot(
        (
            '{"schema_version":1,"entries":['
            f'{{"dn":"{USER_DN}","kind":"user","name":"Alice"}},'
            f'{{"dn":"{GROUP_DN}","kind":"group","name":"Ops",'
            f'"members":["{USER_DN}"]}}'
            ']}'
        ).encode("utf-8"),
        source_id="benchmark-expected",
    )

    with tempfile.TemporaryDirectory() as root:
        transport = FixtureTransport()
        provider = ActiveDirectoryIdentityProvider(
            transport=transport,
            base_dn="DC=example,DC=test",
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
            now=datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc),
        )

    benchmark = benchmark_identity_collection(collected, expected.evidence)
    record = benchmark.to_dict()

    assert transport.calls == 2
    assert transport.closed
    assert benchmark.provider_requests == 2
    assert benchmark.provider_duration_ms == 0
    assert benchmark.expected_coverage_complete
    assert not benchmark.unexpected_evidence_present
    assert benchmark.missed_identities == 0
    assert benchmark.missed_groups == 0
    assert benchmark.missed_memberships == 0
    assert benchmark.invented_memberships == 0
    assert len(benchmark.graph_sha256) == 64
    assert len(benchmark.benchmark_sha256) == 64

    rendered = json.dumps(record, sort_keys=True)
    assert "Alice" not in rendered
    assert USER_DN not in rendered
    assert "Ops" not in rendered

    print(rendered)


if __name__ == "__main__":
    main()
