"""Loopback runtime gate for the v0.43 isolated revocable worker."""

from __future__ import annotations

from datetime import datetime, timezone
import os
import socket
import tempfile
import threading

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
    ValidationWorkerState,
    run_revocable_validation_worker,
)
from nightrecon_shared_core.contracts import EngagementMetadata
from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy
from nightrecon_shared_core.workspace import LocalWorkspace


NOW = datetime(2026, 9, 29, 21, 0, tzinfo=timezone.utc)


def provenance(key):
    return (GraphProvenance("engagement-evidence", key),)


def main():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]


    def serve():
        try:
            connection, _address = listener.accept()
            connection.close()
        finally:
            listener.close()


    server = threading.Thread(target=serve, daemon=True)
    server.start()

    identity = GraphNode.create(
        kind=GraphNodeKind.IDENTITY,
        natural_key="identity:worker-runtime",
        label="Worker runtime identity",
        provenance=provenance("identity"),
    )
    service = GraphNode.create(
        kind=GraphNodeKind.SERVICE,
        natural_key=f"127.0.0.1:{port}/tcp",
        label="loopback",
        provenance=provenance("service"),
        properties=(
            ("address", "127.0.0.1"),
            ("port", str(port)),
            ("protocol", "tcp"),
        ),
    )
    critical = GraphNode.create(
        kind=GraphNodeKind.CRITICAL_ASSET,
        natural_key="critical:worker-runtime",
        label="Worker runtime critical",
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
    option = next(
        item for item in plan.options
        if item.technique_id == "service.tcp-property-proof"
    )
    binding = bind_validation_eligibility_option(graph, option)

    with tempfile.TemporaryDirectory() as root:
        workspace = LocalWorkspace(root)
        workspace.create_engagement(EngagementMetadata(
            engagement_id="eng-worker-runtime",
            name="Worker runtime",
            created_at="2026-09-29T20:00:00+00:00",
            authorization_reference="approval://eng-worker-runtime",
            status="active",
        ))
        workspace.set_execution_policy(EngagementExecutionPolicy(
            engagement_id="eng-worker-runtime",
            scope=("127.0.0.1",),
            valid_from="2026-09-29T20:00:00+00:00",
            valid_until="2026-09-30T01:00:00+00:00",
            max_actions=1,
            permitted_capabilities=("validation.run",),
        ))
        result = run_revocable_validation_worker(
            workspace,
            graph,
            option,
            selected_binding_id=binding.binding_id,
            engagement_id="eng-worker-runtime",
            now=NOW,
        )

    server.join(timeout=2)
    assert result.state is ValidationWorkerState.CONFIRMED
    assert result.actions_used == 1
    assert result.evidence == {
        "transport": "tcp",
        "port": port,
        "state": "open",
    }
    assert result.worker_pid is not None
    assert result.worker_pid != os.getpid()
    print("v0.43 isolated revocable validation worker runtime: passed")



if __name__ == "__main__":
    main()
