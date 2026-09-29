"""v0.43 Batch 4 isolated revocable validation worker tests."""

from __future__ import annotations

from datetime import datetime, timezone
import os
import socket
import tempfile
import threading
import time
import unittest

from nightrecon_red_engine.attack_path_atlas import (
    build_cross_domain_attack_path_atlas,
)
from nightrecon_red_engine.graph_builder import IdentityGraphBuilder
from nightrecon_red_engine.graph_models import (
    GraphEdge,
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
)
from nightrecon_red_engine.validation_adapter_contracts import (
    bind_validation_eligibility_option,
)
from nightrecon_red_engine.validation_candidates import (
    compile_validation_candidates,
)
from nightrecon_red_engine.validation_eligibility import (
    plan_validation_eligibility,
)
from nightrecon_red_engine.validation_worker import (
    ValidationWorkerLimits,
    ValidationWorkerState,
    run_revocable_validation_worker,
)
from nightrecon_shared_core.contracts import EngagementMetadata
from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy
from nightrecon_shared_core.workspace import LocalWorkspace


NOW = datetime(2026, 9, 29, 21, 0, tzinfo=timezone.utc)


def provenance(key):
    return (GraphProvenance("engagement-evidence", key),)


def make_workspace(root, *, scope=("127.0.0.1",), max_actions=3):
    workspace = LocalWorkspace(root)
    workspace.create_engagement(EngagementMetadata(
        engagement_id="eng-worker",
        name="Worker lab",
        created_at="2026-09-29T20:00:00+00:00",
        authorization_reference="approval://eng-worker",
        status="active",
    ))
    workspace.set_execution_policy(EngagementExecutionPolicy(
        engagement_id="eng-worker",
        scope=scope,
        valid_from="2026-09-29T20:00:00+00:00",
        valid_until="2026-09-30T01:00:00+00:00",
        max_actions=max_actions,
        permitted_capabilities=("validation.run",),
    ))
    return workspace


def service_fixture(port, *, tls=False):
    identity = GraphNode.create(
        kind=GraphNodeKind.IDENTITY,
        natural_key="identity:worker",
        label="Worker identity",
        provenance=provenance("identity"),
    )
    properties = [
        ("address", "127.0.0.1"),
        ("port", str(port)),
        ("protocol", "tcp"),
    ]
    if tls:
        properties.append(("tls_certificate_sha256", "a" * 64))
    service = GraphNode.create(
        kind=GraphNodeKind.SERVICE,
        natural_key=f"127.0.0.1:{port}/tcp",
        label="loopback",
        provenance=provenance("service"),
        properties=tuple(properties),
    )
    critical = GraphNode.create(
        kind=GraphNodeKind.CRITICAL_ASSET,
        natural_key="critical:worker",
        label="Worker critical target",
        provenance=provenance("critical"),
    )
    edges = (
        GraphEdge.create(
            source_node_id=identity.node_id,
            target_node_id=service.node_id,
            relationship="correlates-to",
            evidence_state=GraphEvidenceState.INFERRED,
            provenance=provenance("edge-1"),
        ),
        GraphEdge.create(
            source_node_id=service.node_id,
            target_node_id=critical.node_id,
            relationship="evidence-path",
            evidence_state=GraphEvidenceState.OBSERVED,
            provenance=provenance("edge-2"),
        ),
    )
    builder = IdentityGraphBuilder()
    for node in (identity, service, critical):
        builder.add_node(node)
    for edge in edges:
        builder.add_edge(edge)
    graph = builder.build()
    atlas = build_cross_domain_attack_path_atlas(
        graph,
        start_kinds=(GraphNodeKind.IDENTITY,),
    )
    plan = plan_validation_eligibility(
        graph,
        compile_validation_candidates(graph, atlas),
    )
    technique = (
        "service.tls-property-proof"
        if tls
        else "service.tcp-property-proof"
    )
    option = next(
        item for item in plan.options if item.technique_id == technique
    )
    binding = bind_validation_eligibility_option(graph, option)
    return graph, option, binding


def start_listener(*, hold_seconds=0.0):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    accepted = threading.Event()

    def serve():
        try:
            connection, _address = listener.accept()
            accepted.set()
            with connection:
                if hold_seconds:
                    time.sleep(hold_seconds)
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return port, accepted, thread


class ValidationWorkerTests(unittest.TestCase):
    def test_explicit_selected_tcp_proof_runs_in_spawned_worker(self):
        port, _accepted, thread = start_listener()
        graph, option, binding = service_fixture(port)

        with tempfile.TemporaryDirectory() as root:
            result = run_revocable_validation_worker(
                make_workspace(root),
                graph,
                option,
                selected_binding_id=binding.binding_id,
                engagement_id="eng-worker",
                now=NOW,
            )

        thread.join(timeout=2)
        self.assertEqual(result.state, ValidationWorkerState.CONFIRMED)
        self.assertEqual(result.reason_code, "validated")
        self.assertEqual(result.evidence["transport"], "tcp")
        self.assertEqual(result.evidence["port"], port)
        self.assertEqual(result.evidence["state"], "open")
        self.assertEqual(result.actions_used, 1)
        self.assertIsNotNone(result.worker_pid)
        self.assertNotEqual(result.worker_pid, os.getpid())

    def test_out_of_scope_denial_consumes_no_action_and_starts_no_worker(self):
        port, _accepted, thread = start_listener()
        graph, option, binding = service_fixture(port)

        with tempfile.TemporaryDirectory() as root:
            workspace = make_workspace(root, scope=("192.0.2.1",))
            result = run_revocable_validation_worker(
                workspace,
                graph,
                option,
                selected_binding_id=binding.binding_id,
                engagement_id="eng-worker",
                now=NOW,
            )
            policy = workspace.execution_policy("eng-worker")

        self.assertEqual(result.state, ValidationWorkerState.DENIED)
        self.assertEqual(result.reason_code, "target_out_of_scope")
        self.assertEqual(policy.actions_used, 0)
        self.assertIsNone(result.worker_pid)
        # Listener was never contacted; close it by making a local connection.
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                pass
        except OSError:
            pass
        thread.join(timeout=2)

    def test_explicit_binding_selection_is_required_before_authorization(self):
        port, _accepted, thread = start_listener()
        graph, option, _binding = service_fixture(port)

        with tempfile.TemporaryDirectory() as root:
            workspace = make_workspace(root)
            with self.assertRaisesRegex(ValueError, "selected binding"):
                run_revocable_validation_worker(
                    workspace,
                    graph,
                    option,
                    selected_binding_id="validation-binding-wrong",
                    engagement_id="eng-worker",
                    now=NOW,
                )
            self.assertEqual(
                workspace.execution_policy("eng-worker").actions_used,
                0,
            )

        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                pass
        except OSError:
            pass
        thread.join(timeout=2)

    def test_mid_execution_revocation_terminates_worker(self):
        port, accepted, thread = start_listener(hold_seconds=2.5)
        graph, option, binding = service_fixture(port, tls=True)

        with tempfile.TemporaryDirectory() as root:
            workspace = make_workspace(root)

            def revoke():
                accepted.wait(timeout=2)
                LocalWorkspace(root).revoke_execution("eng-worker")

            revoker = threading.Thread(target=revoke, daemon=True)
            revoker.start()
            result = run_revocable_validation_worker(
                workspace,
                graph,
                option,
                selected_binding_id=binding.binding_id,
                engagement_id="eng-worker",
                limits=ValidationWorkerLimits(
                    max_runtime_seconds=4,
                    adapter_timeout_seconds=3,
                    poll_interval_seconds=0.02,
                ),
                now=NOW,
            )
            revoker.join(timeout=2)

        self.assertEqual(result.state, ValidationWorkerState.REVOKED)
        self.assertEqual(result.reason_code, "authorization_revoked")
        self.assertEqual(result.actions_used, 1)
        self.assertEqual(result.evidence, {})
        thread.join(timeout=4)

    def test_one_action_budget_blocks_second_worker(self):
        first_port, _first_accepted, first_thread = start_listener()
        graph, option, binding = service_fixture(first_port)

        with tempfile.TemporaryDirectory() as root:
            workspace = make_workspace(root, max_actions=1)
            first = run_revocable_validation_worker(
                workspace,
                graph,
                option,
                selected_binding_id=binding.binding_id,
                engagement_id="eng-worker",
                now=NOW,
            )
            self.assertEqual(first.state, ValidationWorkerState.CONFIRMED)

            second_port, _second_accepted, second_thread = start_listener()
            graph2, option2, binding2 = service_fixture(second_port)
            second = run_revocable_validation_worker(
                workspace,
                graph2,
                option2,
                selected_binding_id=binding2.binding_id,
                engagement_id="eng-worker",
                now=NOW,
            )

            self.assertEqual(second.state, ValidationWorkerState.DENIED)
            self.assertEqual(second.reason_code, "action_budget_exhausted")
            self.assertEqual(
                workspace.execution_policy("eng-worker").actions_used,
                1,
            )
            try:
                with socket.create_connection(
                    ("127.0.0.1", second_port),
                    timeout=1,
                ):
                    pass
            except OSError:
                pass
            second_thread.join(timeout=2)

        first_thread.join(timeout=2)

    def test_runtime_limit_terminates_blocked_worker(self):
        port, _accepted, thread = start_listener(hold_seconds=2.0)
        graph, option, binding = service_fixture(port, tls=True)

        with tempfile.TemporaryDirectory() as root:
            result = run_revocable_validation_worker(
                make_workspace(root),
                graph,
                option,
                selected_binding_id=binding.binding_id,
                engagement_id="eng-worker",
                limits=ValidationWorkerLimits(
                    max_runtime_seconds=0.35,
                    adapter_timeout_seconds=0.3,
                    poll_interval_seconds=0.02,
                ),
                now=NOW,
            )

        self.assertIn(
            result.state,
            {ValidationWorkerState.TIMED_OUT, ValidationWorkerState.ERROR},
        )
        self.assertEqual(result.actions_used, 1)
        thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
