"""Deterministic, standard-library-only Batch 1 controller.

All inputs are data. Nothing here executes commands, follows filesystem links,
accesses a network, creates branches, persists state, or commits changes.
Expected policy digests and verified identities must come from a trusted caller,
never from the task or candidate. These models are not security capabilities.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
import hashlib
import json
import re
from typing import Mapping


class Rejected(ValueError):
    """Untrusted input or a requested transition failed closed."""


REQUIRED_CHECKS = frozenset({
    "python-suite", "controller-tests", "python-syntax", "dependency-check",
    "red-launcher-smoke", "red-package-boundary",
})


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise Rejected(message)


def _keys(data: object, expected: set[str]) -> dict:
    _require(type(data) is dict and set(data) == expected, "unexpected fields")
    return data


def _integer(value: object, low: int, high: int) -> int:
    _require(type(value) is int and low <= value <= high, "invalid integer")
    return value


def _text(value: object, maximum: int = 4096) -> str:
    _require(type(value) is str and 0 < len(value.strip()) <= maximum,
             "invalid text")
    _require(not any(ord(c) < 32 and c not in "\n\t" for c in value),
             "control character in text")
    return value


def _sha(value: object, length: int = 40) -> str:
    _require(type(value) is str and re.fullmatch(r"[0-9a-f]{%d}" % length, value)
             is not None, "invalid digest")
    return value


def _strings(value: object, maximum: int = 64) -> tuple[str, ...]:
    _require(type(value) is list and 0 < len(value) <= maximum, "invalid list")
    result = tuple(_text(v) for v in value)
    _require(len(result) == len(set(result)), "duplicate list entries")
    return result


def _json(raw: bytes, maximum: int) -> dict:
    _require(type(raw) is bytes and len(raw) <= maximum, "JSON size/type limit")

    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def constant(_value):
        raise Rejected("non-finite JSON number")

    try:
        result = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Rejected("invalid JSON") from exc
    _require(type(result) is dict, "JSON object required")
    return result


def _canonical(data: object) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def path_name(value: object, *, prefix: bool = False) -> str:
    """Portable repository paths; reject normalization and Windows aliases."""
    _require(type(value) is str and 0 < len(value) <= 512, "invalid path")
    path = value[:-1] if prefix and value.endswith("/") else value
    parts = path.split("/")
    reserved = {"con", "prn", "aux", "nul"}
    reserved.update(f"{name}{n}" for name in ("com", "lpt") for n in range(1, 10))
    for part in parts:
        _require(re.fullmatch(r"[A-Za-z0-9_.-]+", part) is not None
                 and part not in (".", "..") and not part.endswith(".")
                 and part.casefold() != ".git"
                 and part.split(".")[0].casefold() not in reserved,
                 "non-canonical path")
    return value


def _covers(scope: str, path: str) -> bool:
    scope, path = scope.casefold(), path.casefold()
    return path.startswith(scope) if scope.endswith("/") else path == scope


def _overlaps(left: str, right: str) -> bool:
    return _covers(left, right) or _covers(right, left)


@dataclass(frozen=True)
class Policy:
    digest: str
    base_sha: str
    branch_prefix: str
    allowed_submitters: tuple[str, ...]
    allowed_roles: tuple[str, ...]
    permitted_paths: tuple[str, ...]
    protected_paths: tuple[str, ...]
    permitted_operations: tuple[str, ...]
    allowed_modes: tuple[str, ...]
    max_task_bytes: int
    max_changed_files: int
    max_changed_bytes: int
    max_repair_attempts: int
    max_runtime_minutes: int
    required_checks: tuple[str, ...]
    allowed_skip_ids: tuple[str, ...]


def load_policy(raw: bytes, *, expected_digest: str) -> Policy:
    """Pin exact policy bytes using an independently trusted SHA-256."""
    _sha(expected_digest, 64)
    _require(type(raw) is bytes and _digest(raw) == expected_digest,
             "policy digest mismatch")
    data = _json(raw, 65536)
    names = set(Policy.__dataclass_fields__) - {"digest"}
    _keys(data, names | {"schema_version", "execution_enabled",
                       "publishing_enabled", "external_assessments_enabled"})
    _require(type(data["schema_version"]) is int and data["schema_version"] == 1,
             "unsupported policy version")
    for flag in ("execution_enabled", "publishing_enabled", "external_assessments_enabled"):
        _require(data[flag] is False, "Batch 1 capabilities must be disabled")
    _sha(data["base_sha"])
    _require(data["branch_prefix"] == "codex/task-", "unsafe branch prefix")
    for name in ("allowed_submitters", "allowed_roles", "permitted_paths",
                 "protected_paths", "permitted_operations", "allowed_modes",
                 "required_checks"):
        data[name] = _strings(data[name])
    _require(type(data["allowed_skip_ids"]) is list and len(data["allowed_skip_ids"]) <= 64,
             "invalid skip allowlist")
    data["allowed_skip_ids"] = tuple(data["allowed_skip_ids"])
    _require(all(type(item) is str for item in data["allowed_skip_ids"]), "invalid skip ID type")
    _require(len(set(data["allowed_skip_ids"])) == len(data["allowed_skip_ids"]), "duplicate skip ID")
    for skip_id in data["allowed_skip_ids"]:
        _require(type(skip_id) is str and re.fullmatch(r"test_[a-z0-9_]+\.[A-Za-z0-9_]+\.test_[a-z0-9_]+", skip_id)
                 is not None, "invalid skip test ID")
    _require(set(data["allowed_roles"]) <= {"admin", "maintain"}, "unsafe role")
    for user in data["allowed_submitters"]:
        _require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", user) is not None,
                 "invalid submitter")
    for name in ("permitted_paths", "protected_paths"):
        for path in data[name]:
            path_name(path, prefix=True)
    # Defense in depth even if a caller pins an unsafe policy revision.
    _require({".github/", "tools/", "AGENTS.md", "tests/test_task_automation.py",
              "tests/test_objective_controller.py", "tests/test_objective_inventory.py",
              "docs/AUTONOMOUS_DEVELOPMENT.md"} <= set(data["protected_paths"]),
             "missing mandatory control protection")
    _require(set(data["permitted_operations"]) <= {"add", "modify", "delete"},
             "unknown operation")
    _require(data["allowed_modes"] == ("100644",), "unsafe file modes")
    for check in data["required_checks"]:
        _require(re.fullmatch(r"[a-z][a-z0-9-]{0,63}", check) is not None,
                 "invalid check identifier")
    _require(REQUIRED_CHECKS <= set(data["required_checks"]), "missing baseline validation")
    for name, high in (("max_task_bytes", 16384), ("max_changed_files", 100),
                       ("max_changed_bytes", 1048576), ("max_runtime_minutes", 120)):
        _integer(data[name], 1, high)
    _integer(data["max_repair_attempts"], 0, 2)
    return Policy(digest=expected_digest, **{name: data[name] for name in names})


@dataclass(frozen=True)
class Task:
    issue_number: int
    revision: int
    base_sha: str
    objective: str
    acceptance_criteria: tuple[str, ...]
    permitted_paths: tuple[str, ...]
    permitted_operations: tuple[str, ...]
    digest: str
    policy_digest: str

    @property
    def task_id(self) -> str:
        return f"issue-{self.issue_number}:r{self.revision}:{self.digest}"

    @property
    def branch(self) -> str:
        return f"codex/task-{self.issue_number}-r{self.revision}-{self.digest[:12]}"


def parse_task(raw: bytes, policy: Policy) -> Task:
    data = _json(raw, policy.max_task_bytes)
    _keys(data, {"schema_version", "issue_number", "revision", "base_sha", "objective",
                 "acceptance_criteria", "permitted_paths", "permitted_operations"})
    _require(type(data["schema_version"]) is int and data["schema_version"] == 1,
             "unsupported task version")
    _integer(data["issue_number"], 1, 2**31 - 1)
    _integer(data["revision"], 1, 999999)
    _require(_sha(data["base_sha"]) == policy.base_sha, "unapproved base commit")
    _text(data["objective"])
    for key in ("acceptance_criteria", "permitted_paths", "permitted_operations"):
        data[key] = _strings(data[key], 20)
    _require(set(data["permitted_operations"]) <= set(policy.permitted_operations),
             "unapproved task operation")
    for path in data["permitted_paths"]:
        path_name(path, prefix=True)
        _require(any(_covers(scope, path) for scope in policy.permitted_paths),
                 "task path outside policy")
        _require(not any(_overlaps(scope, path) for scope in policy.protected_paths),
                 "task path overlaps protected control")
    return Task(**{k: v for k, v in data.items() if k != "schema_version"},
                digest=_digest(_canonical(data)), policy_digest=policy.digest)


@dataclass(frozen=True)
class VerifiedIdentity:
    """Out-of-band adapter evidence, NOT fields accepted from Issue JSON."""

    login: str
    role: str
    repository: str


def admit(task: Task, policy: Policy, identity: VerifiedIdentity,
          *, repository: str, observed_base_sha: str,
          observed_issue_number: int,
          existing_branches: Mapping[str, str]) -> "Run":
    _require(task.policy_digest == policy.digest, "task policy changed")
    _require(identity.repository == repository == "kostekdolata/NightRecon",
             "repository identity mismatch")
    _require(identity.login.casefold() in {u.casefold() for u in policy.allowed_submitters}
             and identity.role in policy.allowed_roles, "unauthorized submitter")
    _require(observed_base_sha == task.base_sha == policy.base_sha,
             "base verification failed")
    _require(type(observed_issue_number) is int and observed_issue_number == task.issue_number,
             "issue identity mismatch")
    _require(not any(branch.removeprefix("refs/heads/").casefold() == task.branch.casefold()
                     for branch in existing_branches), "task branch already exists")
    return replace(Run.pending(task), state=State.ADMITTED)


@dataclass(frozen=True)
class FileEntry:
    mode: str
    content: bytes


@dataclass(frozen=True)
class Change:
    path: str
    operation: str
    old_mode: str | None
    new_mode: str | None


@dataclass(frozen=True)
class Candidate:
    task_id: str
    branch: str
    base_sha: str
    policy_digest: str
    digest: str
    changes: tuple[Change, ...]
    violations: tuple[str, ...]

    @property
    def scope_valid(self) -> bool:
        return not self.violations

    @property
    def publishable(self) -> bool:
        # Scope success is NEVER publication authorization in Batch 1.
        return False


def _snapshot(entries: Mapping[str, FileEntry]) -> tuple:
    _require(len(entries) <= 20000, "snapshot entry limit")
    seen = set()
    total = 0
    records = []
    for path in entries:
        path_name(path)
    for path, entry in sorted(entries.items()):
        _require(path.casefold() not in seen, "case-colliding snapshot paths")
        seen.add(path.casefold())
        _require(type(entry) is FileEntry and type(entry.content) is bytes,
                 "invalid file entry")
        _require(type(entry.mode) is str and entry.mode in {"100644", "100755", "120000", "160000"},
                 "unsupported Git file mode")
        total += len(entry.content)
        _require(total <= 67108864, "snapshot byte limit")
        records.append((path, entry.mode, _digest(entry.content)))
    for path in seen:
        parts = path.split("/")
        _require(not any("/".join(parts[:i]) in seen for i in range(1, len(parts))),
                 "file/symlink ancestor in snapshot")
    return tuple(records)


def inspect_candidate(task: Task, policy: Policy,
                      base: Mapping[str, FileEntry],
                      candidate: Mapping[str, FileEntry]) -> Candidate:
    """Compare COMPLETE inventories; renames are deletion plus addition.

    The future trusted collector must supply both complete inventories. Caller-
    asserted changed-file lists or test stdout cannot establish provenance.
    Symlinks are opaque bytes and are never resolved or followed.
    """
    _require(task.policy_digest == policy.digest, "candidate policy mismatch")
    # Copy caller-owned mappings before validation and digesting.
    base, candidate = dict(base), dict(candidate)
    before, after = _snapshot(base), _snapshot(candidate)
    changes = []
    violations = []
    changed_bytes = 0
    for path in sorted(base.keys() | candidate.keys()):
        old, new = base.get(path), candidate.get(path)
        if old == new:
            continue
        operation = "add" if old is None else "delete" if new is None else "modify"
        changes.append(Change(path, operation, old.mode if old else None,
                              new.mode if new else None))
        changed_bytes += sum(len(entry.content) for entry in (old, new) if entry)
        if operation not in task.permitted_operations:
            violations.append(f"operation_not_permitted:{path}")
        if not any(_covers(scope, path) for scope in policy.permitted_paths):
            violations.append(f"outside_policy:{path}")
        if not any(_covers(scope, path) for scope in task.permitted_paths):
            violations.append(f"outside_task:{path}")
        if any(_covers(scope, path) for scope in policy.protected_paths):
            violations.append(f"protected_path:{path}")
        if any(entry.mode not in policy.allowed_modes for entry in (old, new) if entry):
            violations.append(f"unsafe_mode:{path}")
        if old and new and old.mode != new.mode:
            violations.append(f"mode_change:{path}")
    if not changes:
        violations.append("empty_candidate")
    if len(changes) > policy.max_changed_files:
        violations.append("changed_file_limit")
    if changed_bytes > policy.max_changed_bytes:
        violations.append("changed_byte_limit")
    binding = {"task_id": task.task_id, "base_sha": task.base_sha,
               "policy": policy.digest, "before": before, "after": after}
    return Candidate(task.task_id, task.branch, task.base_sha, policy.digest,
                     _digest(_canonical(binding)), tuple(changes), tuple(violations))


class State(str, Enum):
    PENDING = "pending"
    ADMITTED = "admitted"
    RUNNING = "running"
    VALIDATING = "validating"
    REPAIRING = "repairing"
    BLOCKED = "blocked"
    FAILED = "failed"
    COMPLETED = "completed"


@dataclass(frozen=True)
class Check:
    """Validated observation; provenance must be established by a future collector."""

    name: str
    status: str
    exit_code: int | None
    candidate_digest: str
    tests_run: int | None = None
    passed: int | None = None
    failed: int | None = None
    errors: int | None = None
    skipped: int | None = None
    skip_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        from dataclasses import asdict

        return asdict(self) | {"skip_ids": list(self.skip_ids)}

    def validate(self) -> None:
        _require(type(self.name) is str and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", self.name) is not None,
                 "invalid check name")
        _sha(self.candidate_digest, 64)
        _require(type(self.status) is str and self.status in {"passed", "failed", "blocked", "not_run"},
                 "invalid check status")
        if self.status in {"passed", "failed"}:
            _integer(self.exit_code, 0, 255)
            _require((self.exit_code == 0) == (self.status == "passed"),
                     "check exit/status mismatch")
        else:
            _require(self.exit_code is None, "non-executed check has exit code")
        counts = (self.tests_run, self.passed, self.failed, self.errors, self.skipped)
        _require(type(self.skip_ids) in (tuple, list) and len(self.skip_ids) <= 64
                 and all(type(item) is str for item in self.skip_ids), "invalid skipped test IDs")
        _require(len(set(self.skip_ids)) == len(self.skip_ids), "duplicate skipped test ID")
        if any(value is not None for value in counts):
            for value in counts:
                _integer(value, 0, 1000000)
            _require(self.tests_run == sum(counts[1:]), "inconsistent test counts")
            if self.status == "passed":
                _require(self.passed > 0 and self.failed == self.errors == 0
                         and self.skipped == len(self.skip_ids),
                         "passing check has failed/skipped/empty tests")
            _require(self.status in {"passed", "failed"}, "unexecuted test counts")
        else:
            _require(not self.skip_ids, "skipped IDs without test counts")


@dataclass(frozen=True)
class Run:
    task_id: str
    branch: str
    base_sha: str
    policy_digest: str
    state: State = State.PENDING
    repair_attempts: int = 0
    candidate: Candidate | None = None
    checks: tuple[Check, ...] = ()
    reason: str | None = None

    @classmethod
    def pending(cls, task: Task) -> "Run":
        return cls(task.task_id, task.branch, task.base_sha, task.policy_digest)

    def to_dict(self) -> dict:
        from dataclasses import asdict

        return {
            "schema_version": 1, "task_id": self.task_id, "branch": self.branch,
            "base_sha": self.base_sha, "policy_digest": self.policy_digest,
            "state": self.state.value, "repair_attempts": self.repair_attempts,
            "candidate_digest": self.candidate.digest if self.candidate else None,
            "changed_files": [asdict(c) for c in self.candidate.changes] if self.candidate else [],
            "scope_violations": list(self.candidate.violations) if self.candidate else [],
            "tests": [c.to_dict() for c in self.checks], "ci_results": [],
            "reason": self.reason, "commit_sha": None, "publishable": False,
            "limitations": ["Batch 1 is offline only; no CI collector, executor or publisher.",
                            "Completed means evaluation completed, not committed or published.",
                            "Input provenance must be established independently by a trusted adapter."],
        }


_EDGES = {
    State.PENDING: {State.ADMITTED, State.BLOCKED, State.FAILED},
    State.ADMITTED: {State.RUNNING, State.BLOCKED, State.FAILED},
    State.RUNNING: {State.VALIDATING, State.BLOCKED, State.FAILED},
    State.VALIDATING: {State.REPAIRING, State.COMPLETED, State.BLOCKED, State.FAILED},
    State.REPAIRING: {State.VALIDATING, State.BLOCKED, State.FAILED},
    State.BLOCKED: set(), State.FAILED: set(), State.COMPLETED: set(),
}


def transition(run: Run, target: str, policy: Policy, *,
               candidate: Candidate | None = None, checks: tuple[Check, ...] = (),
               reason: str | None = None) -> Run:
    _require(run.policy_digest == policy.digest and run.base_sha == policy.base_sha,
             "run policy/base mismatch")
    try:
        state = State(target)
    except ValueError as exc:
        raise Rejected("unknown state") from exc
    _require(state in _EDGES[run.state], "illegal state transition")
    _require(state != State.ADMITTED, "admission requires verified identity via admit")
    _integer(run.repair_attempts, 0, policy.max_repair_attempts)
    if state in {State.BLOCKED, State.FAILED}:
        _text(reason, 1024)
        _require(candidate is None and not checks, "terminal transition cannot replace evidence")
        return replace(run, state=state, reason=reason)
    _require(reason is None, "reason only permitted on blocked/failed states")
    if state == State.VALIDATING:
        _require(candidate is not None and not checks, "new candidate required without stale checks")
        _require((candidate.task_id, candidate.branch, candidate.base_sha, candidate.policy_digest)
                 == (run.task_id, run.branch, run.base_sha, run.policy_digest),
                 "candidate binding mismatch")
        return replace(run, state=state, candidate=candidate, checks=())
    if state in {State.COMPLETED, State.REPAIRING}:
        _require(candidate is None and run.candidate is not None, "use the frozen candidate")
        names = set()
        for check in checks:
            _require(type(check) is Check, "invalid check observation")
            check.validate()
            _require(check.name not in names, "duplicate check observation")
            names.add(check.name)
            _require(check.candidate_digest == run.candidate.digest, "stale check observation")
            _require(set(check.skip_ids) <= set(policy.allowed_skip_ids), "unexpected skipped tests")
        if state == State.COMPLETED:
            _require(run.candidate.scope_valid, "candidate scope failed")
            _require(set(policy.required_checks) <= names, "missing required checks")
            _require(all(c.status == "passed" for c in checks), "unresolved validation")
            for check in checks:
                if check.name in {"python-suite", "controller-tests", "red-package-boundary"}:
                    _require(check.tests_run is not None, "test count evidence required")
        else:
            _require(not run.candidate.scope_valid or any(c.status == "failed" for c in checks),
                     "repair requires a failed check or scope failure")
            _require(run.repair_attempts < policy.max_repair_attempts, "repair limit reached")
        return replace(run, state=state, checks=tuple(checks),
                       repair_attempts=run.repair_attempts + (state == State.REPAIRING))
    _require(candidate is None and not checks, "unexpected evidence")
    return replace(run, state=state)


def validate_result(raw: bytes, policy: Policy) -> dict:
    """Validate a serialized Batch 1 record, without trusting its provenance.

    This does not import the record into a run or authorize any side effect.
    JSON Schema is also supplied for external consumers.
    """
    data = _json(raw, 1048576)
    _keys(data, {"schema_version", "task_id", "branch", "base_sha", "policy_digest",
                 "state", "repair_attempts", "candidate_digest", "changed_files",
                 "scope_violations", "tests", "ci_results", "reason", "commit_sha",
                 "publishable", "limitations"})
    _require(type(data["schema_version"]) is int and data["schema_version"] == 1,
             "unsupported result version")
    _require(data["policy_digest"] == policy.digest and data["base_sha"] == policy.base_sha,
             "result policy/base mismatch")
    match = re.fullmatch(r"issue-([1-9][0-9]*):r([1-9][0-9]*):([0-9a-f]{64})",
                         _text(data["task_id"]))
    _require(match is not None, "invalid task ID")
    issue, revision, digest = match.groups()
    _integer(int(issue), 1, 2**31 - 1)
    _integer(int(revision), 1, 999999)
    _require(data["branch"] == f"codex/task-{issue}-r{revision}-{digest[:12]}",
             "result branch mismatch")
    _require(type(data["state"]) is str and data["state"] in {s.value for s in State}, "unknown result state")
    _integer(data["repair_attempts"], 0, policy.max_repair_attempts)
    _require(data["publishable"] is False and data["commit_sha"] is None
             and data["ci_results"] == [], "Batch 1 cannot publish or assert CI results")
    _strings(data["limitations"])
    _require(type(data["changed_files"]) is list and len(data["changed_files"]) <= 20000,
             "invalid result changes")
    paths = set()
    for change in data["changed_files"]:
        _keys(change, {"path", "operation", "old_mode", "new_mode"})
        path = path_name(change["path"])
        _require(path.casefold() not in paths, "duplicate result change")
        paths.add(path.casefold())
        old, new = change["old_mode"], change["new_mode"]
        _require(all(mode is None or (type(mode) is str and mode in {"100644", "100755", "120000", "160000"})
                     for mode in (old, new)), "invalid result mode")
        operation = change["operation"]
        _require((operation == "add" and old is None and new is not None)
                 or (operation == "delete" and old is not None and new is None)
                 or (operation == "modify" and old is not None and new is not None),
                 "result operation/mode mismatch")
    violations = data["scope_violations"]
    _require(type(violations) is list and len(violations) <= 100000, "invalid violations")
    for violation in violations:
        _text(violation)
    if data["candidate_digest"] is not None:
        _sha(data["candidate_digest"], 64)
    else:
        _require(not paths and not violations and not data["tests"], "unbound result evidence")
    _require(type(data["tests"]) is list and len(data["tests"]) <= 128, "invalid checks")
    checks = []
    for observation in data["tests"]:
        _keys(observation, set(Check.__dataclass_fields__))
        check = Check(**observation)
        check.validate()
        _require(set(check.skip_ids) <= set(policy.allowed_skip_ids), "unexpected result skips")
        _require(check.candidate_digest == data["candidate_digest"], "stale result check")
        checks.append(check)
    _require(len({c.name for c in checks}) == len(checks), "duplicate result check")
    if data["state"] in {"blocked", "failed"}:
        _text(data["reason"], 1024)
    else:
        _require(data["reason"] is None, "unexpected result reason")
    if data["state"] in {"pending", "admitted", "running"}:
        _require(data["candidate_digest"] is None, "premature candidate evidence")
    if data["state"] in {"validating", "repairing", "completed"}:
        _require(data["candidate_digest"] is not None, "missing candidate evidence")
    if data["state"] == "validating":
        _require(not checks, "validation observations belong to the next transition")
    if data["state"] == "repairing":
        _require(data["repair_attempts"] > 0
                 and (violations or any(c.status == "failed" for c in checks)),
                 "repair without failed evidence")
    if data["state"] == "completed":
        _require(paths and not violations and len(paths) <= policy.max_changed_files,
                 "non-passing completed candidate")
        _require(set(policy.required_checks) <= {c.name for c in checks}
                 and all(c.status == "passed" for c in checks), "incomplete result checks")
        for check in checks:
            if check.name in {"python-suite", "controller-tests", "red-package-boundary"}:
                _require(check.tests_run is not None, "missing result test counts")
        for change in data["changed_files"]:
            _require(all(mode is None or mode in policy.allowed_modes
                         for mode in (change["old_mode"], change["new_mode"])),
                     "unsafe completed mode")
            _require(any(_covers(scope, change["path"]) for scope in policy.permitted_paths)
                     and not any(_covers(scope, change["path"]) for scope in policy.protected_paths),
                     "unsafe completed path")
    return data
