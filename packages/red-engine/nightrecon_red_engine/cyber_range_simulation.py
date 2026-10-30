"""Isolated cyber-range simulation for high-impact validation scenarios.

The simulator has no socket/process/subprocess/filesystem execution surface.
It models credential access, persistence, privilege escalation, propagation,
lateral movement, destructive impact, and agent commands entirely in memory.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from hashlib import sha256
import json


MAX_RANGE_HOSTS = 64
MAX_RANGE_EVENTS = 512
MAX_SIMULATION_STEPS = 128


class RangeAction(str, Enum):
    CREDENTIAL_ACCESS = "credential-access"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    LATERAL_MOVEMENT = "lateral-movement"
    PROPAGATION = "propagation"
    DESTRUCTIVE_IMPACT = "destructive-impact"
    COLLECTION = "collection"


@dataclass(frozen=True)
class VirtualHost:
    host_id: str
    compromised: bool = False
    privileged: bool = False
    credential_marker: bool = False
    persistence_marker: bool = False
    destructive_marker: bool = False
    collected_marker: bool = False


@dataclass(frozen=True)
class RangeEvent:
    sequence: int
    action: RangeAction
    source_host: str
    target_host: str
    outcome: str
    evidence_id: str


@dataclass(frozen=True)
class RangeSnapshot:
    snapshot_id: str
    hosts: tuple[VirtualHost, ...]
    events: tuple[RangeEvent, ...]


@dataclass(frozen=True)
class RangeReport:
    scenario_id: str
    events: tuple[RangeEvent, ...]
    evidence_ids: tuple[str, ...]
    rollback_snapshot_id: str
    cleaned: bool


@dataclass(frozen=True)
class SimulationPayload:
    payload_id: str
    scenario_id: str
    allowed_actions: tuple[RangeAction, ...]
    max_steps: int
    digest: str

    def to_json(self) -> str:
        return json.dumps({
            "payload_id": self.payload_id,
            "scenario_id": self.scenario_id,
            "allowed_actions": [item.value for item in self.allowed_actions],
            "max_steps": self.max_steps,
            "digest": self.digest,
            "simulation_only": True,
        }, sort_keys=True)


def build_simulation_payload(
    *,
    scenario_id: str,
    allowed_actions: tuple[RangeAction, ...],
    max_steps: int = 32,
) -> SimulationPayload:
    if not scenario_id.strip():
        raise ValueError("scenario_id must not be empty")
    if not allowed_actions:
        raise ValueError("allowed_actions must not be empty")
    if max_steps < 1 or max_steps > MAX_SIMULATION_STEPS:
        raise ValueError(
            f"max_steps must be between 1 and {MAX_SIMULATION_STEPS}"
        )
    normalized = tuple(dict.fromkeys(allowed_actions))
    material = "|".join(
        [scenario_id, str(max_steps)]
        + [item.value for item in normalized]
    )
    digest = sha256(material.encode()).hexdigest()
    return SimulationPayload(
        payload_id="sim-" + digest[:20],
        scenario_id=scenario_id,
        allowed_actions=normalized,
        max_steps=max_steps,
        digest=digest,
    )


class CyberRange:
    def __init__(self, hosts: tuple[VirtualHost, ...]):
        if not hosts:
            raise ValueError("cyber range must contain at least one host")
        if len(hosts) > MAX_RANGE_HOSTS:
            raise ValueError(
                f"cyber range exceeds MAX_RANGE_HOSTS={MAX_RANGE_HOSTS}"
            )
        ids = [host.host_id for host in hosts]
        if any(not item.strip() for item in ids):
            raise ValueError("host_id must not be empty")
        if len(ids) != len(set(ids)):
            raise ValueError("host_id values must be unique")
        self._hosts = {host.host_id: host for host in hosts}
        self._events: list[RangeEvent] = []

    def snapshot(self) -> RangeSnapshot:
        material = "|".join(
            [
                f"{host.host_id}:{int(host.compromised)}:{int(host.privileged)}:"
                f"{int(host.credential_marker)}:{int(host.persistence_marker)}:"
                f"{int(host.destructive_marker)}:{int(host.collected_marker)}"
                for host in sorted(self._hosts.values(), key=lambda item: item.host_id)
            ]
            + [event.evidence_id for event in self._events]
        )
        snapshot_id = "snapshot-" + sha256(material.encode()).hexdigest()[:20]
        return RangeSnapshot(
            snapshot_id=snapshot_id,
            hosts=tuple(sorted(
                self._hosts.values(),
                key=lambda item: item.host_id,
            )),
            events=tuple(self._events),
        )

    def restore(self, snapshot: RangeSnapshot) -> None:
        self._hosts = {host.host_id: host for host in snapshot.hosts}
        self._events = list(snapshot.events)

    def execute(
        self,
        *,
        payload: SimulationPayload,
        source_host: str,
        target_host: str,
        action: RangeAction,
    ) -> RangeEvent:
        if len(self._events) >= min(MAX_RANGE_EVENTS, payload.max_steps):
            raise ValueError("simulation step budget exhausted")
        if action not in payload.allowed_actions:
            raise PermissionError("simulation action is not allowed by payload")
        if source_host not in self._hosts or target_host not in self._hosts:
            raise KeyError("source or target host is not present in range")

        source = self._hosts[source_host]
        target = self._hosts[target_host]
        outcome = "simulated"

        if action is RangeAction.CREDENTIAL_ACCESS:
            target = replace(target, credential_marker=True)
        elif action is RangeAction.PERSISTENCE:
            if not target.compromised:
                outcome = "blocked-precondition"
            else:
                target = replace(target, persistence_marker=True)
        elif action is RangeAction.PRIVILEGE_ESCALATION:
            if not target.compromised:
                outcome = "blocked-precondition"
            else:
                target = replace(target, privileged=True)
        elif action is RangeAction.LATERAL_MOVEMENT:
            if not source.compromised:
                outcome = "blocked-precondition"
            else:
                target = replace(target, compromised=True)
        elif action is RangeAction.PROPAGATION:
            if not source.compromised:
                outcome = "blocked-precondition"
            else:
                target = replace(target, compromised=True)
        elif action is RangeAction.DESTRUCTIVE_IMPACT:
            if not target.privileged:
                outcome = "blocked-precondition"
            else:
                target = replace(target, destructive_marker=True)
        elif action is RangeAction.COLLECTION:
            if not target.compromised:
                outcome = "blocked-precondition"
            else:
                target = replace(target, collected_marker=True)

        self._hosts[target_host] = target
        sequence = len(self._events) + 1
        evidence_material = (
            f"{payload.payload_id}|{sequence}|{action.value}|"
            f"{source_host}|{target_host}|{outcome}"
        )
        event = RangeEvent(
            sequence=sequence,
            action=action,
            source_host=source_host,
            target_host=target_host,
            outcome=outcome,
            evidence_id="range-evidence-" + sha256(
                evidence_material.encode()
            ).hexdigest()[:20],
        )
        self._events.append(event)
        return event

    def run_scenario(
        self,
        *,
        payload: SimulationPayload,
        steps: tuple[tuple[str, str, RangeAction], ...],
        rollback: bool = True,
    ) -> RangeReport:
        if len(steps) > payload.max_steps:
            raise ValueError("scenario exceeds payload step budget")

        before = self.snapshot()
        created: list[RangeEvent] = []
        for source, target, action in steps:
            created.append(self.execute(
                payload=payload,
                source_host=source,
                target_host=target,
                action=action,
            ))

        cleaned = False
        if rollback:
            self.restore(before)
            cleaned = True

        return RangeReport(
            scenario_id=payload.scenario_id,
            events=tuple(created),
            evidence_ids=tuple(event.evidence_id for event in created),
            rollback_snapshot_id=before.snapshot_id,
            cleaned=cleaned,
        )


@dataclass(frozen=True)
class SimulatedAgentSession:
    host_id: str
    active: bool = True

    def run(self, command: str, host: VirtualHost) -> str:
        if not self.active:
            raise ValueError("agent session is closed")
        allowed = {
            "whoami": "administrator" if host.privileged else "standard-user",
            "hostname": host.host_id,
            "status": (
                f"compromised={host.compromised};"
                f"privileged={host.privileged};"
                f"persistence={host.persistence_marker}"
            ),
        }
        if command not in allowed:
            raise ValueError("simulated agent command is not reviewed")
        return allowed[command]

    def close(self) -> "SimulatedAgentSession":
        return SimulatedAgentSession(
            host_id=self.host_id,
            active=False,
        )
