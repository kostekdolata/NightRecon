"""Objective orchestration with fail-closed integration boundaries.

Adapters must be independently sandboxed services. In-process Python objects are
not a credential/security boundary. No production adapter is enabled by default.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .controller import FileEntry, Policy, Rejected, _canonical, _digest, _keys, _require, _strings, _text, inspect_candidate
from .objectives import Approval, Receipt, TrustKey, ValidationFailed, verify_envelope, verify_receipt
from .queue import ObjectiveQueue


DEPLOYMENT_DOMAIN = b"nightrecon-controller-deployment-v1\x00"


@dataclass(frozen=True)
class Batch:
    number: int
    goal: str
    acceptance_criteria: tuple[str, ...]


def validate_plan(data: object, approval: Approval) -> tuple[Batch, ...]:
    _require(type(data) is list and 0 < len(data) <= approval.limits.max_batches,
             "invalid or oversized batch plan")
    result = []
    covered = set()
    for index, item in enumerate(data, 1):
        _keys(item, {"number", "goal", "acceptance_criteria"})
        _require(type(item["number"]) is int and item["number"] == index,
                 "nonsequential plan")
        criteria = _strings(item["acceptance_criteria"], 20)
        _require(set(criteria) <= set(approval.task.acceptance_criteria), "plan expands acceptance scope")
        covered.update(criteria)
        result.append(Batch(index, _text(item["goal"]), criteria))
    _require(covered == set(approval.task.acceptance_criteria), "plan omits acceptance criteria")
    return tuple(result)


@dataclass(frozen=True)
class Deployment:
    capabilities: tuple[str, ...] = ()
    evidence_digest: str | None = None
    expires_at: int = 0
    envelope: bytes | None = None


def verify_deployment(raw: bytes, owner_keys: dict[str, TrustKey], *, now: int) -> Deployment:
    data, _, _ = verify_envelope(raw, DEPLOYMENT_DOMAIN, owner_keys, "deployment-owner")
    _keys(data, {"expires_at", "capabilities", "security_acceptance", "harmless_e2e_run_url",
                 "harmless_e2e_artifact_sha256"})
    from .controller import _integer, _sha
    import re
    _require(_integer(data["expires_at"], 1, 2**53 - 1) > now
             and data["security_acceptance"] is True, "deployment security acceptance gate")
    capabilities = _strings(data["capabilities"], 4)
    _require(set(capabilities) <= {"execute", "push", "merge", "release"}, "unknown deployment capability")
    _require(re.fullmatch(r"https://github\.com/kostekdolata/NightRecon/actions/runs/[1-9][0-9]*",
                         _text(data["harmless_e2e_run_url"])) is not None,
             "harmless end-to-end protected-merge evidence required")
    _sha(data["harmless_e2e_artifact_sha256"], 64)
    return Deployment(capabilities, _digest(_canonical(data)), data["expires_at"], raw)


class Worker(Protocol):
    live: bool

    def plan(self, approval: Approval, tokens: int, cost_microusd: int) -> list[dict]: ...

    def implement(self, approval: Approval, batch: Batch, current: dict[str, FileEntry],
                  failure: str | None, tokens: int, cost_microusd: int) -> dict[str, FileEntry]: ...


class Validator(Protocol):
    live: bool

    def validate(self, approval: Approval, candidate, parent_sha: str, batch: int) -> bytes: ...

    def acceptance(self, approval: Approval, candidate, parent_sha: str) -> bytes: ...


class Publisher(Protocol):
    live: bool

    def reconcile(self, approval: Approval, record: dict, snapshot: dict[str, FileEntry]) -> bool: ...

    def commit_push(self, approval: Approval, candidate, snapshot: dict[str, FileEntry],
                    receipt: Receipt, parent_sha: str, batch: int,
                    idempotency_key: str, deployment: Deployment) -> dict: ...

    def merge(self, approval: Approval, publication: dict, deployment: Deployment) -> dict: ...


class ObjectiveService:
    """Runs dependent batches without asking for a new objective approval.

    Live execution is gated by separately authenticated deployment acceptance.
    Test adapters exercise the full orchestration without network or real agents.
    """

    def __init__(self, queue: ObjectiveQueue, policy: Policy, *, owner_keys,
                 validator_keys, worker: Worker, validator: Validator, publisher: Publisher,
                 deployment: Deployment = Deployment(), clock,
                 attempt_tokens: int = 100000, attempt_cost_microusd: int = 1000000,
                 release_provider=None, release_signing_keys=None, sleeper=None):
        self.queue, self.policy = queue, policy
        self.owner_keys, self.validator_keys = owner_keys, validator_keys
        self.worker, self.validator, self.publisher = worker, validator, publisher
        self.deployment, self.clock = deployment, clock
        self.attempt_tokens, self.attempt_cost = attempt_tokens, attempt_cost_microusd
        self.release_provider, self.release_signing_keys = release_provider, release_signing_keys
        import time
        self.sleeper = sleeper or time.sleep

    def _update(self, record: dict, event: str, **changes) -> dict:
        return self.queue.update(record["objective_id"], worker=record["lease_owner"],
                                 generation=record["lease_generation"], version=record["version"],
                                 now=self.clock(), event=event, changes=changes)

    def _approval(self, objective_id):
        return self.queue.approval(objective_id, self.policy, self.owner_keys, now=self.clock())

    def run(self, objective_id: str, *, worker_id: str,
            base: dict[str, FileEntry], plan: list[dict] | None = None) -> dict:
        if self.queue.expire(objective_id, now=self.clock())["state"] == "blocked":
            return self.report(objective_id)
        record = self.queue.claim(objective_id, worker=worker_id, now=self.clock(), lease_seconds=300)
        if record["state"] == "blocked":
            return self.report(objective_id)
        approval = self._approval(objective_id)
        try:
            live = any(adapter.live for adapter in (self.worker, self.validator, self.publisher))
            if live:
                _require(self.deployment.evidence_digest is not None
                         and self.clock() < self.deployment.expires_at
                         and {"execute", "push", "merge"} <= set(self.deployment.capabilities),
                         "live execution/publishing disabled: security and harmless end-to-end gates missing")
            if approval.release_authorized:
                _require(self.release_provider is not None and self.release_signing_keys
                         and "release" in self.deployment.capabilities,
                         "release signing/broker/security acceptance gate missing")
            _require(record["merge_sha"] is None, "recorded merge needs release/completion reconciliation")
            current = dict(base)
            publication = None
            candidate = None
            if record["commits"]:
                _require(record["plan"] is not None and record["batch"] == len(record["commits"]),
                         "incomplete published batch history")
                import base64
                from .controller import _json
                previous = record["commits"][-1]
                saved = _json(self.queue.artifact(previous["artifact"]), 67108864)
                restored = {}
                for path, entry in saved.items():
                    _keys(entry, {"mode", "content"})
                    _require(type(entry["content"]) is str, "invalid frozen content")
                    restored[path] = FileEntry(entry["mode"], base64.b64decode(entry["content"], validate=True))
                candidate = inspect_candidate(approval.task, self.policy, base, restored)
                _require(candidate.digest == previous["candidate_digest"], "resumed candidate mismatch")
                prior_parent = (record["commits"][-2]["commit_sha"] if record["batch"] > 1
                                else approval.task.base_sha)
                verify_receipt(self.queue.artifact(previous["receipt_artifact"]), approval, candidate,
                    self.policy, self.validator_keys, parent_sha=prior_parent, batch=record["batch"],
                    now=self.clock())
                _require(self.publisher.reconcile(approval, record, restored), "published head/tree reconciliation failed")
                _require(plan is None or plan == record["plan"], "resume cannot replace frozen plan")
                plan, current, publication = record["plan"], restored, previous
                record = self._update(record, "objective_resumed", state="running")
            else:
                record = self._update(record, "objective_started", state="running")
            if plan is None:
                record = self.queue.reserve_attempt(approval, worker=worker_id,
                    generation=record["lease_generation"], version=record["version"], now=self.clock(),
                    tokens=self.attempt_tokens, cost_microusd=self.attempt_cost)
                record = self._update(record, "planning_intent", intent={"kind": "planning"})
                plan = self.worker.plan(approval, self.attempt_tokens, self.attempt_cost)
            batches = validate_plan(plan, approval)
            # Persist the exact plan before any implementation call. Candidate state
            # is never reconstructed from test output or instructions in logs.
            record = self._update(record, "plan_frozen", plan=plan, intent=None)
            published = dict(current)
            for batch in batches[record["batch"]:]:
                failure = None
                for attempt in range(approval.limits.max_repairs_per_batch + 1):
                    self._approval(objective_id)
                    record = self.queue.reserve_attempt(approval, worker=worker_id,
                        generation=record["lease_generation"], version=record["version"], now=self.clock(),
                        tokens=self.attempt_tokens, cost_microusd=self.attempt_cost)
                    record = self._update(record, "implementation_intent", intent={
                        "kind": "implementation", "batch": batch.number, "attempt": attempt})
                    snapshot = self.worker.implement(approval, batch, dict(current), failure,
                                                     self.attempt_tokens, self.attempt_cost)
                    if failure is not None:
                        repair_changes = {path for path in current.keys() | snapshot.keys()
                                          if current.get(path) != snapshot.get(path)}
                        responsible = {path for path in published.keys() | current.keys()
                                       if published.get(path) != current.get(path)}
                        _require(repair_changes <= responsible, "repair touched an unrelated file")
                    candidate = inspect_candidate(approval.task, self.policy, base, snapshot)
                    record = self._update(record, "candidate_frozen", state="validating", repairs=attempt,
                                          intent={"kind": "validation", "candidate": candidate.digest})
                    try:
                        if not candidate.scope_valid:
                            raise ValidationFailed("candidate scope failed")
                        _require(dict(snapshot) != published, "batch has no incremental changes")
                        raw = self.validator.validate(approval, candidate, record["parent_sha"], batch.number)
                        receipt = verify_receipt(raw, approval, candidate, self.policy,
                            self.validator_keys, parent_sha=record["parent_sha"], batch=batch.number,
                            now=self.clock())
                    except ValidationFailed as exc:
                        failure = str(exc)
                        if attempt >= approval.limits.max_repairs_per_batch:
                            raise Rejected("repair limit exhausted: " + failure) from exc
                        record = self._update(record, "repair_requested", state="repairing",
                                              reason=None, repairs=attempt + 1)
                        # Only the failing candidate is supplied for repair. The
                        # original approval and scope remain unchanged.
                        current = dict(snapshot)
                        continue
                    self._approval(objective_id)
                    # Durable write-ahead intent: if the broker call times out,
                    # block for reconciliation instead of issuing a second commit.
                    operation_id = _digest(_canonical({"approval": approval.digest,
                        "batch": batch.number, "parent": record["parent_sha"], "candidate": candidate.digest}))
                    import base64
                    artifact = _canonical({path: {"mode": entry.mode,
                        "content": base64.b64encode(entry.content).decode("ascii")}
                        for path, entry in sorted(snapshot.items())})
                    artifact_digest = self.queue.store_artifact(artifact)
                    receipt_artifact = self.queue.store_artifact(receipt.envelope)
                    record = self._update(record, "publication_intent", intent={
                        "kind": "commit_push", "id": operation_id, "candidate": candidate.digest,
                        "receipt": receipt.digest, "parent": record["parent_sha"],
                        "artifact": artifact_digest, "receipt_artifact": receipt_artifact})
                    publication = self.publisher.commit_push(approval, candidate, dict(snapshot), receipt,
                        record["parent_sha"], batch.number, operation_id, self.deployment)
                    from .controller import _sha
                    _sha(publication["commit_sha"])
                    _require(publication["branch"] == approval.task.branch
                             and publication["candidate_digest"] == candidate.digest,
                             "publisher receipt mismatch")
                    record = self._update(record, "batch_published", state="running", intent=None,
                        parent_sha=publication["commit_sha"], batch=batch.number, repairs=0,
                        commits=record["commits"] + [publication | {
                            "batch": batch.number, "receipt_digest": receipt.digest,
                            "artifact": artifact_digest, "receipt_artifact": receipt_artifact,
                            "validator": receipt.validator,
                            "changed_files": [c.path for c in candidate.changes],
                            "tests": [c.to_dict() for c in receipt.checks],
                            "ci_results": list(receipt.run_urls)}])
                    current = dict(snapshot)
                    published = dict(snapshot)
                    break
            record = self._update(record, "objective_acceptance_started", state="validating",
                                  intent={"kind": "acceptance"})
            acceptance = self.validator.acceptance(approval, candidate, record["parent_sha"])
            data, _, _ = verify_envelope(acceptance, b"nightrecon-objective-acceptance-v1\x00",
                                         self.validator_keys, "validator")
            _keys(data, {"approval_digest", "candidate_digest", "head_sha", "criteria", "passed"})
            _require(data["approval_digest"] == approval.digest and data["candidate_digest"] == candidate.digest
                     and data["head_sha"] == record["parent_sha"] and data["passed"] is True
                     and set(_strings(data["criteria"], 20)) == set(approval.task.acceptance_criteria),
                     "objective acceptance not satisfied")
            self._approval(objective_id)
            record = self._update(record, "merge_intent", intent={"kind": "merge", "head": record["parent_sha"]})
            from .github_gateway import GatePending
            for _ in range(60):
                self._approval(objective_id)
                try:
                    merged = self.publisher.merge(approval, publication, self.deployment)
                    break
                except GatePending:
                    record = self._update(record, "waiting_for_required_ci",
                        lease_until=min(self.clock() + 300, record["deadline"]))
                    self.sleeper(5)
            else:
                raise Rejected("required CI did not finish within bounded polling allowance")
            _require(merged.get("merged") is True, "protected merge gate not satisfied")
            from .controller import _sha
            _sha(merged["merge_sha"])
            record = self._update(record, "merge_completed", intent=None, merge_sha=merged["merge_sha"])
            if approval.release_authorized:
                self._approval(objective_id)
                material = self.release_provider(approval, merged["merge_sha"])
                record = self._update(record, "release_intent", intent={"kind": "release", "tag": approval.release_tag})
                release_result = self.publisher.release(approval, manifest=material["manifest"],
                    signing_keys=self.release_signing_keys, artifacts=material["artifacts"],
                    merge_sha=merged["merge_sha"], deployment=self.deployment)
                _require(release_result.get("tag_name") == approval.release_tag
                         and release_result.get("draft") is False, "release acknowledgement uncertain")
                record = self._update(record, "release_completed", intent=None, release_result=release_result)
            self._update(record, "objective_completed", state="completed", intent=None)
        except (Rejected, TimeoutError, OSError) as exc:
            return self._blocked(record, str(exc))
        except Exception:
            # Never interpret or echo an arbitrary adapter exception as an
            # instruction; unknown failures cannot authorize publication.
            return self._blocked(record, "untrusted adapter response or execution failed")
        return self.report(objective_id)

    def _blocked(self, record, reason):
        # Do not erase a pending irreversible intent; recovery must reconcile it.
        try:
            self._update(record, "objective_blocked", state="blocked", reason=reason[:1024])
        except Rejected:
            # A timed-out/lost lease cannot authorize another side effect.
            self.queue.expire(record["objective_id"], now=self.clock())
        report = self.report(record["objective_id"])
        report["state"] = "blocked"
        report["reason"] = reason[:1024]
        return report

    def report(self, objective_id: str) -> dict:
        record = self.queue.read(objective_id)
        return {"schema_version": 1, **record,
                "changed_files": sorted({p for c in record["commits"] for p in c["changed_files"]}),
                "tests": [test for c in record["commits"] for test in c["tests"]],
                "ci_results": [url for c in record["commits"] for url in c["ci_results"]],
                "operational": False,
                "limitations": ["Live deployment has not passed the protected-merge end-to-end gate.",
                                 "Adapter services must isolate coding, validation and publisher credentials.",
                                 "Budget reservations require provider-side enforcement; local timeout does not cancel remote work.",
                                 "Live release publication requires separately accepted signing and release services."]}
