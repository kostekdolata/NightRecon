"""Isolated revocable worker boundary for reviewed read-only validation.

Batch 4 is the first v0.43 execution layer. Each selected validation binding is
run in a fresh spawned child process with a minimal typed request. The parent
owns authorization, action-budget reservation, revocation monitoring, runtime
limits, result-size limits, and Batch 3 postcondition validation.

The child has no workspace handle, credentials, command/payload surface, shell,
script engine, or generic request template. Only fixed reviewed read-only proof
adapters are dispatchable.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
import http.client
import ipaddress
import json
import multiprocessing
import os
import socket
import ssl
import time
from typing import Callable, Mapping, Any

from nightrecon_red_engine.controlled_validation import ValidationObservation
from nightrecon_red_engine.graph_models import GraphNode, IdentityGraph
from nightrecon_red_engine.validation_adapter_contracts import (
    BUILTIN_VALIDATION_ADAPTER_CONTRACT_REGISTRY,
    ValidationAdapterBinding,
    bind_validation_eligibility_option,
    check_validation_observation_contract,
)
from nightrecon_red_engine.validation_eligibility import ValidationEligibilityOption
from nightrecon_red_engine.validation_techniques import (
    BUILTIN_VALIDATION_TECHNIQUE_REGISTRY,
)
from nightrecon_shared_core.engagement_policy import evaluate_reserved_action
from nightrecon_shared_core.workspace import LocalWorkspace


_FIXED_TECHNIQUES = frozenset({
    "service.tcp-property-proof",
    "service.tls-property-proof",
    "web.http-policy-proof",
})
_SECURITY_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)
_SHA256_RE = __import__("re").compile(r"^[0-9a-f]{64}$")


class ValidationWorkerState(str, Enum):
    DENIED = "denied"
    CONFIRMED = "confirmed"
    NOT_CONFIRMED = "not-confirmed"
    REVOKED = "revoked"
    TIMED_OUT = "timed-out"
    CONTRACT_REJECTED = "contract-rejected"
    ERROR = "error"


@dataclass(frozen=True)
class ValidationWorkerLimits:
    max_runtime_seconds: float = 5.0
    adapter_timeout_seconds: float = 2.0
    poll_interval_seconds: float = 0.05
    max_result_bytes: int = 16_384

    def __post_init__(self) -> None:
        for field in (
            "max_runtime_seconds",
            "adapter_timeout_seconds",
            "poll_interval_seconds",
        ):
            value = getattr(self, field)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{field} must be numeric")
            if value <= 0:
                raise ValueError(f"{field} must be positive")
        if self.max_runtime_seconds > 15:
            raise ValueError("max_runtime_seconds must not exceed 15 seconds")
        if self.adapter_timeout_seconds > 5:
            raise ValueError("adapter_timeout_seconds must not exceed 5 seconds")
        if self.adapter_timeout_seconds > self.max_runtime_seconds:
            raise ValueError(
                "adapter_timeout_seconds must not exceed max_runtime_seconds"
            )
        if not 0.02 <= self.poll_interval_seconds <= 0.5:
            raise ValueError(
                "poll_interval_seconds must be between 0.02 and 0.5 seconds"
            )
        if (
            isinstance(self.max_result_bytes, bool)
            or not isinstance(self.max_result_bytes, int)
            or not 1_024 <= self.max_result_bytes <= 65_536
        ):
            raise ValueError(
                "max_result_bytes must be between 1024 and 65536"
            )


@dataclass(frozen=True)
class ValidationWorkerTarget:
    authorization_target: str
    host: str
    port: int
    scheme: str = ""
    expected_certificate_sha256: str = ""

    def __post_init__(self) -> None:
        if not self.authorization_target or (
            self.authorization_target != self.authorization_target.strip()
        ):
            raise ValueError("authorization_target must be nonblank and trimmed")
        if not self.host or self.host != self.host.strip():
            raise ValueError("host must be nonblank and trimmed")
        if (
            isinstance(self.port, bool)
            or not isinstance(self.port, int)
            or not 1 <= self.port <= 65_535
        ):
            raise ValueError("port must be between 1 and 65535")
        if self.scheme and self.scheme not in {"http", "https"}:
            raise ValueError("scheme must be http or https")
        if self.expected_certificate_sha256 and (
            _SHA256_RE.fullmatch(self.expected_certificate_sha256) is None
        ):
            raise ValueError(
                "expected_certificate_sha256 must be lowercase SHA-256 hex"
            )


@dataclass(frozen=True)
class ValidationWorkerRequest:
    binding_id: str
    technique_id: str
    contract_id: str
    target: ValidationWorkerTarget
    adapter_timeout_seconds: float


@dataclass(frozen=True)
class ValidationWorkerResult:
    engagement_id: str
    binding_id: str
    technique_id: str
    target: str
    state: ValidationWorkerState
    reason_code: str
    summary: str
    evidence: Mapping[str, Any]
    limitations: tuple[str, ...]
    actions_used: int
    remaining_actions: int
    worker_pid: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "engagement_id": self.engagement_id,
            "binding_id": self.binding_id,
            "technique_id": self.technique_id,
            "target": self.target,
            "state": self.state.value,
            "reason_code": self.reason_code,
            "summary": self.summary,
            "evidence": dict(self.evidence),
            "limitations": list(self.limitations),
            "actions_used": self.actions_used,
            "remaining_actions": self.remaining_actions,
            "worker_pid": self.worker_pid,
        }


def _target_node(graph: IdentityGraph, binding: ValidationAdapterBinding) -> GraphNode:
    for node in graph.nodes:
        if node.node_id == binding.target_node_id:
            return node
    raise ValueError("validation binding target node is missing from graph")


def _canonical_host(value: str) -> bool:
    if not value or value != value.strip():
        return False
    try:
        return str(ipaddress.ip_address(value)) == value
    except ValueError:
        return value.casefold().rstrip(".") == value and not any(
            char.isspace() for char in value
        )


def _worker_target(
    graph: IdentityGraph,
    binding: ValidationAdapterBinding,
) -> ValidationWorkerTarget:
    node = _target_node(graph, binding)
    properties = dict(node.properties)

    if binding.technique_id in {
        "service.tcp-property-proof",
        "service.tls-property-proof",
    }:
        host = properties.get("address", "")
        if not _canonical_host(host):
            raise ValueError("service worker target address is not canonical")
        try:
            port = int(properties.get("port", ""))
        except ValueError as exc:
            raise ValueError("service worker target port is invalid") from exc
        fingerprint = (
            properties.get("tls_certificate_sha256", "")
            if binding.technique_id == "service.tls-property-proof"
            else ""
        )
        return ValidationWorkerTarget(
            authorization_target=host,
            host=host,
            port=port,
            expected_certificate_sha256=fingerprint,
        )

    if binding.technique_id == "web.http-policy-proof":
        host = properties.get("origin_host", "")
        if not _canonical_host(host):
            raise ValueError("web worker target host is not canonical")
        try:
            port = int(properties.get("origin_port", ""))
        except ValueError as exc:
            raise ValueError("web worker target port is invalid") from exc
        return ValidationWorkerTarget(
            authorization_target=host,
            host=host,
            port=port,
            scheme=properties.get("origin_scheme", ""),
        )

    raise ValueError("validation technique has no Batch 4 worker adapter")


def _tcp_property_proof(request: ValidationWorkerRequest) -> ValidationObservation:
    with socket.create_connection(
        (request.target.host, request.target.port),
        timeout=request.adapter_timeout_seconds,
    ):
        pass
    return ValidationObservation(
        confirmed=True,
        summary="Selected TCP service accepted a bounded connection.",
        evidence={
            "transport": "tcp",
            "port": request.target.port,
            "state": "open",
        },
        limitations=(
            "Connection proof only; no authentication or exploitability verdict.",
        ),
    )


def _tls_property_proof(request: ValidationWorkerRequest) -> ValidationObservation:
    expected = request.target.expected_certificate_sha256
    if _SHA256_RE.fullmatch(expected) is None:
        raise ValueError("TLS proof requires an exact expected certificate SHA-256")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection(
        (request.target.host, request.target.port),
        timeout=request.adapter_timeout_seconds,
    ) as raw:
        raw.settimeout(request.adapter_timeout_seconds)
        with context.wrap_socket(raw, server_hostname=None) as tls_socket:
            certificate = tls_socket.getpeercert(binary_form=True)
            if not certificate:
                raise ValueError("TLS peer did not present a certificate")
            fingerprint = sha256(certificate).hexdigest()
            cipher = tls_socket.cipher()
            evidence = {
                "tls_version": tls_socket.version() or "unknown",
                "cipher": "" if cipher is None else cipher[0],
                "certificate_sha256": fingerprint,
            }
            return ValidationObservation(
                confirmed=fingerprint == expected,
                summary=(
                    "Observed TLS certificate matched the selected evidence."
                    if fingerprint == expected
                    else "Observed TLS certificate did not match the selected evidence."
                ),
                evidence=evidence,
                limitations=(
                    "Certificate fingerprint proof only; certificate-chain trust "
                    "is not asserted by this adapter.",
                ),
            )


def _http_policy_proof(request: ValidationWorkerRequest) -> ValidationObservation:
    if request.target.scheme == "https":
        connection = http.client.HTTPSConnection(
            request.target.host,
            request.target.port,
            timeout=request.adapter_timeout_seconds,
            context=ssl.create_default_context(),
        )
    elif request.target.scheme == "http":
        connection = http.client.HTTPConnection(
            request.target.host,
            request.target.port,
            timeout=request.adapter_timeout_seconds,
        )
    else:
        raise ValueError("HTTP proof requires an explicit http or https scheme")

    try:
        connection.request(
            "HEAD",
            "/",
            headers={
                "User-Agent": "NightRecon-Red-Validation/0.43",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        headers = {
            key.lower()
            for key, _value in response.getheaders()
            if isinstance(key, str)
        }
        security_headers = tuple(
            key for key in _SECURITY_HEADERS if key in headers
        )
        return ValidationObservation(
            confirmed=True,
            summary="Received a bounded HTTP response-policy observation.",
            evidence={
                "status_code": response.status,
                "security_headers": security_headers,
            },
            limitations=(
                "HEAD / policy proof only; response body was not requested.",
            ),
        )
    finally:
        connection.close()


def _execute_fixed_request(request: ValidationWorkerRequest) -> ValidationObservation:
    if request.technique_id not in _FIXED_TECHNIQUES:
        raise ValueError("worker technique is not in the fixed reviewed set")
    if request.technique_id == "service.tcp-property-proof":
        return _tcp_property_proof(request)
    if request.technique_id == "service.tls-property-proof":
        return _tls_property_proof(request)
    return _http_policy_proof(request)


def _worker_entry(send_conn, request: ValidationWorkerRequest) -> None:
    try:
        observation = _execute_fixed_request(request)
        send_conn.send(("observation", os.getpid(), observation))
    except BaseException:
        try:
            send_conn.send(("error", os.getpid(), "adapter_error"))
        except BaseException:
            pass
    finally:
        try:
            send_conn.close()
        except BaseException:
            pass


def _terminate(process) -> None:
    if process.is_alive():
        process.terminate()
        process.join(timeout=1)
    if process.is_alive() and hasattr(process, "kill"):
        process.kill()
        process.join(timeout=1)


def _current_time(
    fixed_now: datetime | None,
    now_provider: Callable[[], datetime] | None,
) -> datetime:
    if now_provider is not None:
        current = now_provider()
    elif fixed_now is not None:
        current = fixed_now
    else:
        current = datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("worker authorization time must include a timezone")
    return current


def _reserved_authorization(
    workspace_root,
    *,
    engagement_id: str,
    target: str,
    impact: str,
    approval_present: bool,
    reserved_actions_used: int,
    expected_max_actions: int,
    current: datetime,
):
    fresh = LocalWorkspace(workspace_root)
    policy = fresh.execution_policy(engagement_id)
    if policy.max_actions != expected_max_actions:
        raise ValueError("engagement action budget changed during worker lease")
    if policy.actions_used < reserved_actions_used:
        raise ValueError("engagement action reservation regressed")
    metadata = fresh.envelope(engagement_id).metadata
    status = None if metadata is None else metadata.status
    return evaluate_reserved_action(
        policy,
        engagement_status=status,
        capability="validation.run",
        target=target,
        impact=impact,
        approval_present=approval_present,
        now=current,
    )


def _result_size(observation: ValidationObservation) -> int:
    payload = {
        "confirmed": observation.confirmed,
        "summary": observation.summary,
        "evidence": dict(observation.evidence),
        "limitations": list(observation.limitations),
    }
    return len(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def run_revocable_validation_worker(
    workspace: LocalWorkspace,
    graph: IdentityGraph,
    option: ValidationEligibilityOption,
    *,
    selected_binding_id: str,
    engagement_id: str,
    approval_present: bool = False,
    limits: ValidationWorkerLimits | None = None,
    now: datetime | None = None,
    now_provider: Callable[[], datetime] | None = None,
) -> ValidationWorkerResult:
    """Execute one explicitly selected reviewed proof in a spawned worker."""

    if not selected_binding_id or (
        selected_binding_id != selected_binding_id.strip()
    ):
        raise ValueError("selected_binding_id must be nonblank and trimmed")
    if not engagement_id or engagement_id != engagement_id.strip():
        raise ValueError("engagement_id must be nonblank and trimmed")

    active = limits or ValidationWorkerLimits()
    binding = bind_validation_eligibility_option(graph, option)
    if binding.binding_id != selected_binding_id:
        raise ValueError("selected binding does not match eligibility option")
    if binding.execution_mode != "contract-only":
        raise ValueError("validation binding must remain contract-only")
    if binding.side_effect_mode != "none":
        raise ValueError("validation binding must declare no side effects")
    if binding.adapter_kind != "read-only-proof":
        raise ValueError("validation binding adapter kind is not executable")
    if binding.technique_id not in _FIXED_TECHNIQUES:
        raise ValueError("validation binding has no fixed Batch 4 adapter")

    technique = BUILTIN_VALIDATION_TECHNIQUE_REGISTRY.get(
        binding.technique_id
    )
    contract = BUILTIN_VALIDATION_ADAPTER_CONTRACT_REGISTRY.for_technique(
        binding.technique_id
    )
    target = _worker_target(graph, binding)
    effective_impact = (
        "high" if binding.requires_approval else binding.impact
    )
    initial_now = _current_time(now, now_provider)

    decision = workspace.authorize_action(
        engagement_id,
        capability="validation.run",
        target=target.authorization_target,
        impact=effective_impact,
        approval_present=approval_present,
        consume=True,
        now=initial_now,
    )
    if not decision.allowed:
        return ValidationWorkerResult(
            engagement_id=engagement_id,
            binding_id=binding.binding_id,
            technique_id=binding.technique_id,
            target=target.authorization_target,
            state=ValidationWorkerState.DENIED,
            reason_code=decision.reason_code,
            summary=decision.reason,
            evidence={},
            limitations=(),
            actions_used=decision.actions_used,
            remaining_actions=decision.remaining_actions,
        )

    request = ValidationWorkerRequest(
        binding_id=binding.binding_id,
        technique_id=binding.technique_id,
        contract_id=contract.contract_id,
        target=target,
        adapter_timeout_seconds=active.adapter_timeout_seconds,
    )

    try:
        lease = _reserved_authorization(
            workspace.root,
            engagement_id=engagement_id,
            target=target.authorization_target,
            impact=effective_impact,
            approval_present=approval_present,
            reserved_actions_used=decision.actions_used,
            expected_max_actions=decision.max_actions,
            current=_current_time(now, now_provider),
        )
    except Exception:
        return ValidationWorkerResult(
            engagement_id=engagement_id,
            binding_id=binding.binding_id,
            technique_id=binding.technique_id,
            target=target.authorization_target,
            state=ValidationWorkerState.ERROR,
            reason_code="lease_recheck_failed",
            summary="Validation worker lease could not be re-checked safely.",
            evidence={},
            limitations=("No worker process was started.",),
            actions_used=decision.actions_used,
            remaining_actions=decision.remaining_actions,
        )

    if not lease.allowed:
        return ValidationWorkerResult(
            engagement_id=engagement_id,
            binding_id=binding.binding_id,
            technique_id=binding.technique_id,
            target=target.authorization_target,
            state=ValidationWorkerState.REVOKED,
            reason_code=lease.reason_code,
            summary=lease.reason,
            evidence={},
            limitations=("Authorization changed before worker start.",),
            actions_used=lease.actions_used,
            remaining_actions=lease.remaining_actions,
        )

    context = multiprocessing.get_context("spawn")
    recv_conn, send_conn = context.Pipe(duplex=False)
    process = context.Process(
        target=_worker_entry,
        args=(send_conn, request),
        daemon=True,
    )
    try:
        process.start()
    except Exception:
        recv_conn.close()
        send_conn.close()
        return ValidationWorkerResult(
            engagement_id=engagement_id,
            binding_id=binding.binding_id,
            technique_id=binding.technique_id,
            target=target.authorization_target,
            state=ValidationWorkerState.ERROR,
            reason_code="worker_start_failed",
            summary="Validation worker could not be started safely.",
            evidence={},
            limitations=(),
            actions_used=decision.actions_used,
            remaining_actions=decision.remaining_actions,
        )
    finally:
        try:
            send_conn.close()
        except BaseException:
            pass

    started = time.monotonic()
    worker_pid = process.pid

    try:
        while True:
            if recv_conn.poll(active.poll_interval_seconds):
                try:
                    message = recv_conn.recv()
                except EOFError:
                    message = ("error", worker_pid, "worker_channel_closed")
                break

            elapsed = time.monotonic() - started
            if elapsed >= active.max_runtime_seconds:
                _terminate(process)
                return ValidationWorkerResult(
                    engagement_id=engagement_id,
                    binding_id=binding.binding_id,
                    technique_id=binding.technique_id,
                    target=target.authorization_target,
                    state=ValidationWorkerState.TIMED_OUT,
                    reason_code="worker_runtime_limit",
                    summary="Validation worker exceeded its hard runtime limit.",
                    evidence={},
                    limitations=("Worker process was terminated.",),
                    actions_used=decision.actions_used,
                    remaining_actions=decision.remaining_actions,
                    worker_pid=worker_pid,
                )

            try:
                lease = _reserved_authorization(
                    workspace.root,
                    engagement_id=engagement_id,
                    target=target.authorization_target,
                    impact=effective_impact,
                    approval_present=approval_present,
                    reserved_actions_used=decision.actions_used,
                    expected_max_actions=decision.max_actions,
                    current=_current_time(now, now_provider),
                )
            except Exception:
                _terminate(process)
                return ValidationWorkerResult(
                    engagement_id=engagement_id,
                    binding_id=binding.binding_id,
                    technique_id=binding.technique_id,
                    target=target.authorization_target,
                    state=ValidationWorkerState.ERROR,
                    reason_code="lease_recheck_failed",
                    summary="Validation worker lease re-check failed closed.",
                    evidence={},
                    limitations=("Worker process was terminated.",),
                    actions_used=decision.actions_used,
                    remaining_actions=decision.remaining_actions,
                    worker_pid=worker_pid,
                )

            if not lease.allowed:
                _terminate(process)
                return ValidationWorkerResult(
                    engagement_id=engagement_id,
                    binding_id=binding.binding_id,
                    technique_id=binding.technique_id,
                    target=target.authorization_target,
                    state=ValidationWorkerState.REVOKED,
                    reason_code=lease.reason_code,
                    summary=lease.reason,
                    evidence={},
                    limitations=("Worker process was terminated on authorization change.",),
                    actions_used=lease.actions_used,
                    remaining_actions=lease.remaining_actions,
                    worker_pid=worker_pid,
                )

            if not process.is_alive():
                if recv_conn.poll():
                    message = recv_conn.recv()
                else:
                    message = ("error", worker_pid, "worker_exited")
                break

        process.join(timeout=1)
        if process.is_alive():
            _terminate(process)

        kind, returned_pid, payload = message
        worker_pid = returned_pid or worker_pid
        if kind != "observation" or not isinstance(payload, ValidationObservation):
            return ValidationWorkerResult(
                engagement_id=engagement_id,
                binding_id=binding.binding_id,
                technique_id=binding.technique_id,
                target=target.authorization_target,
                state=ValidationWorkerState.ERROR,
                reason_code="adapter_error",
                summary="Read-only proof adapter failed safely.",
                evidence={},
                limitations=("No adapter exception detail was retained.",),
                actions_used=decision.actions_used,
                remaining_actions=decision.remaining_actions,
                worker_pid=worker_pid,
            )

        try:
            size = _result_size(payload)
        except Exception:
            return ValidationWorkerResult(
                engagement_id=engagement_id,
                binding_id=binding.binding_id,
                technique_id=binding.technique_id,
                target=target.authorization_target,
                state=ValidationWorkerState.ERROR,
                reason_code="worker_result_invalid",
                summary="Validation worker returned non-serializable evidence.",
                evidence={},
                limitations=(),
                actions_used=decision.actions_used,
                remaining_actions=decision.remaining_actions,
                worker_pid=worker_pid,
            )
        if size > active.max_result_bytes:
            return ValidationWorkerResult(
                engagement_id=engagement_id,
                binding_id=binding.binding_id,
                technique_id=binding.technique_id,
                target=target.authorization_target,
                state=ValidationWorkerState.ERROR,
                reason_code="worker_result_too_large",
                summary="Validation worker result exceeded the hard output limit.",
                evidence={},
                limitations=(),
                actions_used=decision.actions_used,
                remaining_actions=decision.remaining_actions,
                worker_pid=worker_pid,
            )

        postconditions = check_validation_observation_contract(contract, payload)
        if not postconditions.valid:
            return ValidationWorkerResult(
                engagement_id=engagement_id,
                binding_id=binding.binding_id,
                technique_id=binding.technique_id,
                target=target.authorization_target,
                state=ValidationWorkerState.CONTRACT_REJECTED,
                reason_code=postconditions.reason,
                summary="Validation evidence did not satisfy the reviewed contract.",
                evidence={},
                limitations=(),
                actions_used=decision.actions_used,
                remaining_actions=decision.remaining_actions,
                worker_pid=worker_pid,
            )

        return ValidationWorkerResult(
            engagement_id=engagement_id,
            binding_id=binding.binding_id,
            technique_id=binding.technique_id,
            target=target.authorization_target,
            state=(
                ValidationWorkerState.CONFIRMED
                if payload.confirmed
                else ValidationWorkerState.NOT_CONFIRMED
            ),
            reason_code=(
                "validated"
                if payload.confirmed
                else "not_confirmed"
            ),
            summary=payload.summary,
            evidence=dict(payload.evidence),
            limitations=payload.limitations,
            actions_used=decision.actions_used,
            remaining_actions=decision.remaining_actions,
            worker_pid=worker_pid,
        )
    finally:
        try:
            recv_conn.close()
        finally:
            if process.is_alive():
                _terminate(process)
