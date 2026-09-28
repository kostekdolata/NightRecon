"""Policy-constrained plan-only autonomous Red operator.

Agents can propose capability identifiers and targets, never shell commands.
The compiler validates every step against a fixed capability catalog and the
engagement authorization policy without consuming action budget or executing
network activity.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from nightrecon_shared_core.workspace import LocalWorkspace


def _required(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field} must be a nonblank, trimmed string")
    return value


@dataclass(frozen=True)
class OperatorCapability:
    capability_id: str
    description: str
    impact: str = "standard"

    def __post_init__(self) -> None:
        _required(self.capability_id, "capability_id")
        _required(self.description, "description")
        if self.impact not in {"low", "standard", "high"}:
            raise ValueError("impact must be low, standard, or high")


DEFAULT_OPERATOR_CAPABILITIES: tuple[OperatorCapability, ...] = (
    OperatorCapability("discovery", "Bounded host discovery."),
    OperatorCapability("scan", "Bounded service and assessment scan."),
    OperatorCapability("web.crawl", "Bounded HTTP(S) crawl."),
    OperatorCapability("api.probe", "Bounded GET/HEAD API probe."),
    OperatorCapability("identity.collect", "Read-only identity collection."),
    OperatorCapability("validation.run", "Controlled validation proof.", "high"),
)


@dataclass(frozen=True)
class OperatorContext:
    engagement_id: str
    goal: str
    evidence_types: tuple[str, ...] = ()
    max_steps: int = 8

    def __post_init__(self) -> None:
        _required(self.engagement_id, "engagement_id")
        _required(self.goal, "goal")
        if not isinstance(self.max_steps, int) or isinstance(self.max_steps, bool):
            raise ValueError("max_steps must be an integer")
        if self.max_steps < 1 or self.max_steps > 32:
            raise ValueError("max_steps must be between 1 and 32")


@dataclass(frozen=True)
class OperatorProposal:
    capability_id: str
    target: str
    rationale: str
    approval_present: bool = False

    def __post_init__(self) -> None:
        _required(self.capability_id, "capability_id")
        _required(self.target, "target")
        _required(self.rationale, "rationale")


class PlanningAgent(Protocol):
    def propose(self, context: OperatorContext) -> tuple[OperatorProposal, ...]: ...


@dataclass(frozen=True)
class CompiledOperatorStep:
    index: int
    capability_id: str
    target: str
    rationale: str
    status: str
    reason_code: str
    reason: str
    impact: str


@dataclass(frozen=True)
class AutonomousOperatorPlan:
    engagement_id: str
    goal: str
    steps: tuple[CompiledOperatorStep, ...]
    truncated: bool
    execution_mode: str = "plan-only"
    limitations: tuple[str, ...] = (
        "No command, adapter, or network action was executed.",
        "Allowed plan steps still require a separate execution decision.",
    )


def compile_autonomous_plan(
    workspace: LocalWorkspace,
    agent: PlanningAgent,
    context: OperatorContext,
    *,
    capabilities: tuple[OperatorCapability, ...] = DEFAULT_OPERATOR_CAPABILITIES,
    now: datetime | None = None,
) -> AutonomousOperatorPlan:
    catalog = {item.capability_id: item for item in capabilities}
    if len(catalog) != len(capabilities):
        raise ValueError("operator capability IDs must be unique")

    proposals = agent.propose(context)
    if not isinstance(proposals, tuple):
        raise ValueError("planning agent must return a tuple of proposals")
    truncated = len(proposals) > context.max_steps
    selected = proposals[:context.max_steps]
    steps: list[CompiledOperatorStep] = []

    for index, proposal in enumerate(selected, start=1):
        capability = catalog.get(proposal.capability_id)
        if capability is None:
            steps.append(CompiledOperatorStep(
                index=index,
                capability_id=proposal.capability_id,
                target=proposal.target,
                rationale=proposal.rationale,
                status="blocked",
                reason_code="unknown_capability",
                reason="proposal is not in the fixed Red operator capability catalog",
                impact="unknown",
            ))
            continue

        decision = workspace.authorize_action(
            context.engagement_id,
            capability=capability.capability_id,
            target=proposal.target,
            impact=capability.impact,
            approval_present=proposal.approval_present,
            consume=False,
            now=now,
        )
        steps.append(CompiledOperatorStep(
            index=index,
            capability_id=capability.capability_id,
            target=proposal.target,
            rationale=proposal.rationale,
            status="allowed" if decision.allowed else "blocked",
            reason_code=decision.reason_code,
            reason=decision.reason,
            impact=capability.impact,
        ))

    return AutonomousOperatorPlan(
        engagement_id=context.engagement_id,
        goal=context.goal,
        steps=tuple(steps),
        truncated=truncated,
    )
