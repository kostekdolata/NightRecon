"""Cloud/hybrid intelligence is bounded, read-only, and graph compatible."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import tempfile
import unittest

from nightrecon_red_engine.cloud_hybrid_intelligence import (
    CloudCollectionDenied,
    CloudCollectionRequest,
    CloudHybridLimits,
    collect_authorized_cloud_intelligence,
    import_cloud_hybrid_snapshot,
)
from nightrecon_red_engine.unified_attack_graph import build_unified_attack_graph
from nightrecon_shared_core.contracts import EngagementMetadata
from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy
from nightrecon_shared_core.workspace import LocalWorkspace


def snapshot():
    return json.dumps({
        "schema_version": 1,
        "resources": [
            {"provider": "azure", "id": "vm-1", "kind": "virtual-machine", "name": "Finance VM"},
            {"provider": "aws", "id": "bucket-1", "kind": "object-storage", "name": "Reports Bucket"},
        ],
        "identities": [
            {"provider": "entra", "id": "alice", "name": "Alice"},
        ],
        "relationships": [
            {
                "source_type": "identity", "source_provider": "entra", "source_id": "alice",
                "target_type": "resource", "target_provider": "azure", "target_id": "vm-1",
                "relationship": "owner",
            },
            {
                "source_type": "identity", "source_provider": "entra", "source_id": "missing",
                "target_type": "resource", "target_provider": "aws", "target_id": "bucket-1",
                "relationship": "reader",
            },
        ],
    }, separators=(",", ":")).encode()


class FakeProvider:
    def __init__(self, payload):
        self.payload = payload
        self.calls = 0

    def collect_normalized_snapshot(self, request):
        self.calls += 1
        return self.payload


def workspace(root):
    ws = LocalWorkspace(root)
    ws.create_engagement(EngagementMetadata(
        engagement_id="eng-cloud",
        name="Cloud lab",
        created_at="2026-09-28T00:00:00+00:00",
        authorization_reference="approval://eng-cloud",
        status="active",
    ))
    ws.set_execution_policy(EngagementExecutionPolicy(
        engagement_id="eng-cloud",
        scope=("management.example.test",),
        valid_from="2026-09-28T00:00:00+00:00",
        valid_until="2026-09-29T00:00:00+00:00",
        max_actions=3,
        permitted_capabilities=("cloud.collect",),
    ))
    return ws


class CloudHybridIntelligenceTests(unittest.TestCase):
    def test_multi_provider_snapshot_projects_into_unified_graph(self):
        imported = import_cloud_hybrid_snapshot(
            snapshot(),
            engagement_id="eng-cloud",
            source_id="cloud-export-1",
            observed_at="2026-09-28T12:00:00+00:00",
        )
        self.assertEqual(imported.providers, ("aws", "azure", "entra"))
        self.assertEqual(imported.unresolved_relationships, 1)
        graph = build_unified_attack_graph(imported.records)
        self.assertEqual(graph.unresolved_records, ())
        self.assertEqual(len(graph.graph.nodes), 3)
        self.assertEqual(len(graph.graph.edges), 1)
        self.assertEqual(graph.graph.edges[0].relationship, "owner")

    def test_authorization_denial_prevents_provider_call(self):
        with tempfile.TemporaryDirectory() as root:
            provider = FakeProvider(snapshot())
            with self.assertRaises(CloudCollectionDenied) as denied:
                collect_authorized_cloud_intelligence(
                    workspace(root), provider,
                    CloudCollectionRequest(
                        engagement_id="eng-cloud",
                        source_id="cloud-live-1",
                        target="outside.example.test",
                    ),
                    now=datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc),
                )
            self.assertEqual(denied.exception.reason_code, "target_out_of_scope")
            self.assertEqual(provider.calls, 0)

    def test_authorized_provider_consumes_one_action(self):
        with tempfile.TemporaryDirectory() as root:
            provider = FakeProvider(snapshot())
            result = collect_authorized_cloud_intelligence(
                workspace(root), provider,
                CloudCollectionRequest(
                    engagement_id="eng-cloud",
                    source_id="cloud-live-1",
                    target="management.example.test",
                ),
                now=datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc),
            )
            self.assertEqual(provider.calls, 1)
            self.assertGreater(len(result.records), 0)
            self.assertEqual(
                LocalWorkspace(root).execution_policy("eng-cloud").actions_used, 1
            )


    def test_allowlisted_correlation_properties_project_into_unified_graph(self):
        payload = json.dumps({
            "schema_version": 1,
            "resources": [{
                "provider": "azure",
                "id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
                "kind": "virtual-machine",
                "name": "Finance VM",
                "properties": {
                    "azure_tenant_id": "tenant-1",
                    "azure_subscription_id": "sub-1",
                    "azure_resource_id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
                    "private_ip": "10.20.30.40",
                    "hostname": "finance-vm.example.test",
                },
            }],
            "identities": [{
                "provider": "entra",
                "id": "object-1",
                "name": "Managed Identity",
                "properties": {
                    "entra_tenant_id": "tenant-1",
                    "entra_object_id": "object-1",
                },
            }],
            "relationships": [],
        }, separators=(",", ":")).encode()

        imported = import_cloud_hybrid_snapshot(
            payload,
            engagement_id="eng-cloud",
            source_id="cloud-correlation-contract",
            observed_at="2026-09-29T14:00:00+00:00",
        )
        graph = build_unified_attack_graph(imported.records)
        self.assertEqual(graph.unresolved_records, ())

        resource = next(
            node for node in graph.graph.nodes
            if node.natural_key.startswith("cloud:azure:resource:")
        )
        self.assertEqual(
            dict(resource.properties),
            {
                "azure_resource_id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
                "azure_subscription_id": "sub-1",
                "azure_tenant_id": "tenant-1",
                "cloud_provider": "azure",
                "cloud_resource_id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
                "cloud_resource_kind": "virtual-machine",
                "hostname": "finance-vm.example.test",
                "private_ip": "10.20.30.40",
            },
        )

        identity = next(
            node for node in graph.graph.nodes
            if node.natural_key == "cloud:entra:identity:object-1"
        )
        self.assertEqual(
            dict(identity.properties),
            {
                "cloud_identity_id": "object-1",
                "cloud_provider": "entra",
                "entra_object_id": "object-1",
                "entra_tenant_id": "tenant-1",
            },
        )

    def test_provider_specific_correlation_properties_fail_closed(self):
        bad = json.dumps({
            "schema_version": 1,
            "resources": [{
                "provider": "aws",
                "id": "i-123",
                "kind": "virtual-machine",
                "name": "App",
                "properties": {"azure_resource_id": "/subscriptions/not-aws"},
            }],
            "identities": [],
            "relationships": [],
        }).encode()
        with self.assertRaisesRegex(ValueError, "unsupported fields"):
            import_cloud_hybrid_snapshot(
                bad,
                engagement_id="eng-cloud",
                source_id="source",
                observed_at="2026-09-29T14:00:00+00:00",
            )

    def test_secret_like_correlation_properties_are_rejected(self):
        bad = json.dumps({
            "schema_version": 1,
            "resources": [{
                "provider": "aws",
                "id": "i-123",
                "kind": "virtual-machine",
                "name": "App",
                "properties": {"access_token": "secret"},
            }],
            "identities": [],
            "relationships": [],
        }).encode()
        with self.assertRaisesRegex(ValueError, "unsupported fields"):
            import_cloud_hybrid_snapshot(
                bad,
                engagement_id="eng-cloud",
                source_id="source",
                observed_at="2026-09-29T14:00:00+00:00",
            )

    def test_network_correlation_values_must_already_be_canonical(self):
        for properties in (
            {"private_ip": "2001:0db8::1"},
            {"hostname": "Finance-VM.Example.Test."},
        ):
            with self.subTest(properties=properties):
                bad = json.dumps({
                    "schema_version": 1,
                    "resources": [{
                        "provider": "azure",
                        "id": "vm-1",
                        "kind": "virtual-machine",
                        "name": "Finance VM",
                        "properties": properties,
                    }],
                    "identities": [],
                    "relationships": [],
                }).encode()
                with self.assertRaisesRegex(ValueError, "canonical"):
                    import_cloud_hybrid_snapshot(
                        bad,
                        engagement_id="eng-cloud",
                        source_id="source",
                        observed_at="2026-09-29T14:00:00+00:00",
                    )

    def test_schema_rejects_secret_or_unexpected_fields(self):
        bad = json.dumps({
            "schema_version": 1,
            "resources": [{
                "provider": "aws", "id": "x", "kind": "vm", "name": "x",
                "access_token": "secret",
            }],
            "identities": [],
            "relationships": [],
        }).encode()
        with self.assertRaisesRegex(ValueError, "unsupported fields"):
            import_cloud_hybrid_snapshot(
                bad,
                engagement_id="eng-cloud",
                source_id="source",
                observed_at="2026-09-28T12:00:00+00:00",
            )

    def test_limits_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "max_resources"):
            import_cloud_hybrid_snapshot(
                snapshot(),
                engagement_id="eng-cloud",
                source_id="source",
                observed_at="2026-09-28T12:00:00+00:00",
                limits=CloudHybridLimits(max_resources=1),
            )


if __name__ == "__main__":
    unittest.main()
