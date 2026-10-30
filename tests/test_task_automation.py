"""Offline controller boundaries; no GitHub, model invocation or target activity."""

from dataclasses import FrozenInstanceError, replace
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
# The existing script runner discovers top-level test modules rather than
# installing development-only tools into the Night product distributions.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.task_automation.controller import (
    Candidate, Check, FileEntry, Rejected, Run, State, VerifiedIdentity,
    admit, inspect_candidate, load_policy, parse_task, path_name, transition,
    validate_result,
)


BASE = "09707e49116b6021fa7bb695c1979aeb240b4fca"
REPO = "kostekdolata/NightRecon"


def encoded(data):
    return json.dumps(data).encode()


def file(content=b"content", mode="100644"):
    return FileEntry(mode, content)


class TaskControllerTests(unittest.TestCase):
    def setUp(self):
        self.raw = (ROOT / ".github/codex/task-policy.json").read_bytes()
        self.policy = load_policy(self.raw, expected_digest=hashlib.sha256(self.raw).hexdigest())
        self.payload = {
            "schema_version": 1, "issue_number": 200, "revision": 1,
            "base_sha": BASE, "objective": "Add one regression test",
            "acceptance_criteria": ["Offline regression reproduces the bug"],
            "permitted_paths": ["tests/test_example.py"],
            "permitted_operations": ["add", "modify"],
        }
        self.task = parse_task(encoded(self.payload), self.policy)
        self.identity = VerifiedIdentity("kostekdolata", "admin", REPO)

    def admitted(self, **kwargs):
        options = dict(repository=REPO, observed_base_sha=BASE,
                       observed_issue_number=200, existing_branches={})
        options.update(kwargs)
        return admit(self.task, self.policy, self.identity, **options)

    def candidate(self, base=None, after=None):
        return inspect_candidate(self.task, self.policy, base or {},
                                 {"tests/test_example.py": file()} if after is None else after)

    def validating(self, candidate=None):
        run = transition(self.admitted(), "running", self.policy)
        return transition(run, "validating", self.policy,
                          candidate=candidate or self.candidate())

    def passing(self, candidate):
        return tuple(Check(name, "passed", 0, candidate.digest, 1, 1, 0, 0, 0)
                     for name in self.policy.required_checks)

    def completed(self):
        run = self.validating()
        return transition(run, "completed", self.policy, checks=self.passing(run.candidate))

    def test_valid_task_has_stable_identity_and_is_immutable(self):
        reordered = dict(reversed(list(self.payload.items())))
        self.assertEqual(self.task, parse_task(encoded(reordered), self.policy))
        self.assertRegex(self.task.branch, r"^codex/task-200-r1-[a-f0-9]{12}$")
        with self.assertRaises(FrozenInstanceError):
            self.task.objective = "replace"

    def test_task_revision_and_content_change_identity(self):
        for key, value in (("revision", 2), ("objective", "Different objective")):
            changed = parse_task(encoded(self.payload | {key: value}), self.policy)
            self.assertNotEqual(self.task.task_id, changed.task_id)
            self.assertNotEqual(self.task.branch, changed.branch)

    def test_invalid_task_fields_fail_closed(self):
        for key, value in (("schema_version", True), ("issue_number", False),
                           ("issue_number", 0), ("revision", -1), ("revision", 1.5),
                           ("base_sha", "f" * 40), ("objective", "  "),
                           ("objective", "x\x00y"), ("acceptance_criteria", []),
                           ("acceptance_criteria", ["x", "x"]),
                           ("permitted_operations", ["execute"]),
                           ("permitted_paths", ["installer/windows/evil.ps1"])):
            with self.subTest(key=key, value=value), self.assertRaises(Rejected):
                parse_task(encoded(self.payload | {key: value}), self.policy)

    def test_task_cannot_supply_identity_commands_or_publication_authority(self):
        for key in ("submitter", "role", "command", "branch", "publishable", "commit_sha"):
            with self.subTest(key=key), self.assertRaises(Rejected):
                parse_task(encoded(self.payload | {key: "untrusted"}), self.policy)

    def test_malformed_duplicate_nonfinite_oversized_and_missing_json_rejected(self):
        for raw in (b"{", b"[]", b'{"schema_version":1,"schema_version":1}',
                    b'{"revision":NaN}', b" " * 16385, encoded({}),
                    b'"\xff"', b"[" * 2000):
            with self.subTest(raw=raw[:60]), self.assertRaises(Rejected):
                parse_task(raw, self.policy)

    def test_portable_paths_reject_traversal_and_aliases(self):
        for path in ("../x", "/tmp/x", "tests//x", "tests/./x", "tests/../x",
                     "tests\\x", "C:/x", "tests/x:stream", "tests/x.",
                     "tests/CON.txt", "tests/com1", ".git/config", "tests/.GIT/x",
                     "tests/é.py", "tests/x\n.py", "tests/", ""):
            with self.subTest(path=path), self.assertRaises(Rejected):
                path_name(path)
        self.assertEqual(path_name("tests/", prefix=True), "tests/")

    def test_task_cannot_request_protected_controls_or_broad_overlapping_scope(self):
        for path in ("tools/", ".github/codex/task-policy.json", "tests/",
                     "tests/test_task_automation.py", "docs/",
                     "nightrecon/scope.py", "nightrecon/SCOPE.py"):
            with self.subTest(path=path), self.assertRaises(Rejected):
                parse_task(encoded(self.payload | {"permitted_paths": [path]}), self.policy)

    def test_policy_pin_detects_any_byte_change(self):
        with self.assertRaises(Rejected):
            load_policy(self.raw + b"\n", expected_digest=self.policy.digest)

    def test_policy_rejects_unsafe_even_if_new_digest_supplied(self):
        for key, value in (("execution_enabled", True), ("publishing_enabled", True),
                           ("external_assessments_enabled", True), ("branch_prefix", "master"),
                           ("allowed_roles", ["read"]), ("max_repair_attempts", 3),
                           ("max_changed_files", True), ("allowed_modes", ["120000"]),
                           ("protected_paths", [".github/"]), ("required_checks", [])):
            raw = encoded(json.loads(self.raw) | {key: value})
            with self.subTest(key=key), self.assertRaises(Rejected):
                load_policy(raw, expected_digest=hashlib.sha256(raw).hexdigest())

    def test_policy_cannot_replace_baseline_checks_with_a_success_message(self):
        raw = encoded(json.loads(self.raw) | {"required_checks": ["all-tests-passed"]})
        with self.assertRaises(Rejected):
            load_policy(raw, expected_digest=hashlib.sha256(raw).hexdigest())

    def test_policy_pin_must_be_valid_sha256(self):
        with self.assertRaises(Rejected):
            load_policy(self.raw, expected_digest="not-a-pin")

    def test_verified_owner_is_admitted_only_for_exact_repository_and_base(self):
        run = self.admitted()
        self.assertEqual(run.state, State.ADMITTED)
        for kwargs in ({"repository": "other/repo"}, {"observed_base_sha": "a" * 40},
                       {"observed_issue_number": 201}, {"observed_issue_number": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(Rejected):
                self.admitted(**kwargs)

    def test_unauthorized_submitter_and_role_rejected(self):
        for identity in (VerifiedIdentity("attacker", "admin", REPO),
                         VerifiedIdentity("kostekdolata", "read", REPO),
                         VerifiedIdentity("kostekdolata", "write", REPO),
                         VerifiedIdentity("kostekdolata", "admin", "other/repo")):
            with self.subTest(identity=identity), self.assertRaises(Rejected):
                admit(self.task, self.policy, identity, repository=REPO,
                      observed_base_sha=BASE, observed_issue_number=200, existing_branches={})

    def test_existing_task_branch_is_conflict_even_at_same_base(self):
        for branch in (self.task.branch, self.task.branch.upper(), "refs/heads/" + self.task.branch):
            with self.subTest(branch=branch), self.assertRaises(Rejected):
                self.admitted(existing_branches={branch: BASE})
        self.assertEqual(self.admitted(existing_branches={"master": BASE}).state, State.ADMITTED)

    def test_generic_transition_cannot_bypass_admission(self):
        with self.assertRaises(Rejected):
            transition(Run.pending(self.task), "admitted", self.policy)

    def test_task_and_run_are_bound_to_policy_digest(self):
        changed_policy = replace(self.policy, digest="f" * 64)
        with self.assertRaises(Rejected):
            inspect_candidate(self.task, changed_policy, {}, {})
        with self.assertRaises(Rejected):
            transition(self.admitted(), "running", changed_policy)
        with self.assertRaises(Rejected):
            admit(self.task, changed_policy, self.identity, repository=REPO,
                  observed_base_sha=BASE, observed_issue_number=200, existing_branches={})

    def test_addition_and_modification_are_detected(self):
        added = self.candidate()
        modified = self.candidate({"tests/test_example.py": file(b"old")})
        self.assertTrue(added.scope_valid)
        self.assertEqual(added.changes[0].operation, "add")
        self.assertTrue(modified.scope_valid)
        self.assertEqual(modified.changes[0].operation, "modify")

    def test_deletion_requires_explicit_task_operation(self):
        base = {"tests/test_example.py": file()}
        denied = self.candidate(base, {})
        self.assertIn("operation_not_permitted:tests/test_example.py", denied.violations)
        task = parse_task(encoded(self.payload | {"permitted_operations": ["delete"]}), self.policy)
        accepted = inspect_candidate(task, self.policy, base, {})
        self.assertTrue(accepted.scope_valid)
        self.assertEqual(accepted.changes[0].operation, "delete")

    def test_out_of_scope_edit_and_untracked_addition_are_not_ignored(self):
        for path in ("tests/unrelated.py", "nightrecon/unrelated.py", "elsewhere/file"):
            with self.subTest(path=path):
                report = self.candidate(after={path: file()})
                self.assertFalse(report.scope_valid)
                self.assertIn(f"outside_task:{path}", report.violations)

    def test_protected_paths_rejected_for_add_modify_delete_and_case_alias(self):
        for path in (".github/codex/task-policy.json", "tools/evil.py",
                     "tests/test_task_automation.py", "nightrecon/SCOPE.py"):
            for before, after in (({}, {path: file()}), ({path: file()}, {}),
                                  ({path: file()}, {path: file(b"changed")})):
                with self.subTest(path=path, before=before, after=after):
                    report = self.candidate(before, after)
                    self.assertIn(f"protected_path:{path}", report.violations)

    def test_symlinks_gitlinks_and_executable_additions_are_not_publishable(self):
        for mode in ("120000", "160000", "100755"):
            with self.subTest(mode=mode):
                report = self.candidate(after={"tests/test_example.py": file(b"../../outside", mode)})
                self.assertFalse(report.scope_valid)
                self.assertFalse(report.publishable)
                self.assertIn("unsafe_mode:tests/test_example.py", report.violations)

    def test_mode_only_change_and_unsafe_deletion_are_detected(self):
        report = self.candidate({"tests/test_example.py": file(mode="100755")})
        self.assertIn("mode_change:tests/test_example.py", report.violations)
        deleted = self.candidate({"tests/test_example.py": file(mode="120000")}, {})
        self.assertIn("unsafe_mode:tests/test_example.py", deleted.violations)

    def test_symlink_ancestor_and_case_collision_fail_closed(self):
        for after in ({"tests": file(b"/tmp", "120000"), "tests/test_example.py": file()},
                      {"tests/a.py": file(), "tests/A.py": file()}):
            with self.subTest(after=after), self.assertRaises(Rejected):
                self.candidate(after=after)

    def test_invalid_paths_and_entries_are_not_normalized_or_followed(self):
        for after in ({"tests/../other": file()}, {"tests/x": file(mode="100600")},
                      {"tests/x": file("not bytes")}, {"tests/x": file(mode=[])}):
            with self.subTest(after=after), self.assertRaises(Rejected):
                self.candidate(after=after)

    def test_rename_is_bounded_deletion_plus_addition(self):
        report = self.candidate({"tests/old.py": file()}, {"tests/test_example.py": file()})
        self.assertEqual([c.operation for c in report.changes], ["delete", "add"])
        self.assertFalse(report.scope_valid)

    def test_empty_candidate_fails_and_preserves_unchanged_files(self):
        original = {"tests/test_example.py": file(), "nightrecon/scope.py": file()}
        copy = original.copy()
        report = self.candidate(original, copy)
        self.assertEqual(report.violations, ("empty_candidate",))
        self.assertEqual(original, copy)

    def test_change_limits_include_deleted_and_previous_content(self):
        policy = replace(self.policy, max_changed_bytes=3, max_changed_files=1)
        task = replace(self.task, permitted_paths=("tests/example/",))
        report = inspect_candidate(task, policy, {"tests/example/old": file(b"abcd")},
                                   {"tests/example/new": file(b"x")})
        self.assertIn("changed_byte_limit", report.violations)
        self.assertIn("changed_file_limit", report.violations)

    def test_candidate_digest_binds_full_inventory_modes_task_and_base(self):
        candidate = self.candidate()
        same = self.candidate(after=dict(reversed(list({"tests/test_example.py": file()}.items()))))
        self.assertEqual(candidate.digest, same.digest)
        changed = self.candidate(after={"tests/test_example.py": file(b"different")})
        self.assertNotEqual(candidate.digest, changed.digest)
        extra = self.candidate(after={"tests/test_example.py": file(), "docs/unrelated": file()})
        self.assertNotEqual(candidate.digest, extra.digest)
        other_task = replace(self.task, revision=2)
        other = inspect_candidate(other_task, self.policy, {}, {"tests/test_example.py": file()})
        self.assertNotEqual(candidate.digest, other.digest)

    def test_candidate_binding_cannot_be_swapped_into_run(self):
        run = transition(self.admitted(), "running", self.policy)
        for key, value in (("task_id", "other"), ("branch", "master"),
                           ("base_sha", "f" * 40), ("policy_digest", "f" * 64)):
            with self.subTest(key=key), self.assertRaises(Rejected):
                transition(run, "validating", self.policy,
                           candidate=replace(self.candidate(), **{key: value}))

    def test_completed_offline_evaluation_is_never_publishable(self):
        run = self.completed()
        self.assertEqual(run.state, State.COMPLETED)
        self.assertFalse(run.candidate.publishable)
        data = validate_result(encoded(run.to_dict()), self.policy)
        self.assertFalse(data["publishable"])
        self.assertIsNone(data["commit_sha"])
        self.assertEqual(data["ci_results"], [])

    def test_completion_requires_every_required_check(self):
        run = self.validating()
        with self.assertRaises(Rejected):
            transition(run, "completed", self.policy, checks=self.passing(run.candidate)[:-1])

    def test_failed_blocked_and_not_run_checks_prevent_completion(self):
        run = self.validating()
        for status, code in (("failed", 1), ("blocked", None), ("not_run", None)):
            checks = list(self.passing(run.candidate))
            checks[0] = Check(checks[0].name, status, code, run.candidate.digest)
            with self.subTest(status=status), self.assertRaises(Rejected):
                transition(run, "completed", self.policy, checks=tuple(checks))

    def test_extra_failed_check_also_blocks_completion(self):
        run = self.validating()
        checks = self.passing(run.candidate) + (Check("extra", "failed", 1, run.candidate.digest),)
        with self.assertRaises(Rejected):
            transition(run, "completed", self.policy, checks=checks)

    def test_duplicate_stale_missing_counts_and_forged_test_output_rejected(self):
        run = self.validating()
        good = self.passing(run.candidate)
        for checks in (good + (good[0],), (replace(good[0], candidate_digest="f" * 64),) + good[1:],
                       (Check(good[0].name, "passed", 0, run.candidate.digest),) + good[1:],
                       ("all tests passed",)):
            with self.subTest(checks=checks), self.assertRaises(Rejected):
                transition(run, "completed", self.policy, checks=checks)

    def test_invalid_exit_codes_and_counts_are_not_success(self):
        check = Check("python-suite", "passed", 0, self.candidate().digest, 1, 1, 0, 0, 0)
        for fields in ({"exit_code": 1}, {"exit_code": False}, {"tests_run": 0, "passed": 0},
                       {"failed": 1}, {"skipped": 1, "passed": 0}, {"errors": True},
                       {"status": "not_run"}, {"status": []}, {"name": None}):
            with self.subTest(fields=fields), self.assertRaises(Rejected):
                replace(check, **fields).validate()

    def test_scope_failure_prevents_completion_despite_passing_tests(self):
        run = self.validating(self.candidate(after={"tests/unrelated.py": file()}))
        with self.assertRaises(Rejected):
            transition(run, "completed", self.policy, checks=self.passing(run.candidate))

    def test_repair_requires_failure_and_is_bounded(self):
        run = self.validating()
        with self.assertRaises(Rejected):
            transition(run, "repairing", self.policy, checks=self.passing(run.candidate))
        for attempt in (1, 2):
            failed = (Check("python-suite", "failed", 1, run.candidate.digest),)
            run = transition(run, "repairing", self.policy, checks=failed)
            self.assertEqual(run.repair_attempts, attempt)
            run = transition(run, "validating", self.policy, candidate=self.candidate())
            self.assertEqual(run.checks, ())
        with self.assertRaises(Rejected):
            transition(run, "repairing", self.policy, checks=failed)

    def test_repaired_candidate_requires_fresh_complete_validation(self):
        run = self.validating()
        old_checks = self.passing(run.candidate)
        failed = (Check("python-suite", "failed", 1, run.candidate.digest),)
        run = transition(run, "repairing", self.policy, checks=failed)
        new = self.candidate(after={"tests/test_example.py": file(b"fixed")})
        run = transition(run, "validating", self.policy, candidate=new)
        with self.assertRaises(Rejected):
            transition(run, "completed", self.policy, checks=old_checks)
        completed = transition(run, "completed", self.policy, checks=self.passing(new))
        self.assertEqual(completed.repair_attempts, 1)

    def test_new_validation_rejects_stale_checks(self):
        running = transition(self.admitted(), "running", self.policy)
        with self.assertRaises(Rejected):
            transition(running, "validating", self.policy, candidate=self.candidate(),
                       checks=self.passing(self.candidate()))

    def test_blocked_and_failed_preserve_evidence_and_are_terminal(self):
        validating = self.validating()
        for state in ("blocked", "failed"):
            terminal = transition(validating, state, self.policy, reason="required check unavailable")
            self.assertEqual(terminal.candidate, validating.candidate)
            validate_result(encoded(terminal.to_dict()), self.policy)
            for target in State:
                with self.subTest(state=state, target=target), self.assertRaises(Rejected):
                    transition(terminal, target.value, self.policy)
        with self.assertRaises(Rejected):
            transition(validating, "failed", self.policy)

    def test_illegal_state_shortcuts_and_unknown_states_are_rejected(self):
        for start, target in ((Run.pending(self.task), "completed"),
                              (self.admitted(), "validating"), (self.admitted(), "repairing"),
                              (self.admitted(), "unknown"), (self.completed(), "running")):
            with self.subTest(target=target), self.assertRaises(Rejected):
                transition(start, target, self.policy)

    def test_all_legitimate_state_results_round_trip(self):
        pending = Run.pending(self.task)
        admitted = self.admitted()
        running = transition(admitted, "running", self.policy)
        validating = self.validating()
        repairing = transition(validating, "repairing", self.policy,
                               checks=(Check("python-suite", "failed", 1, validating.candidate.digest),))
        records = (pending, admitted, running, validating, repairing, self.completed(),
                   transition(pending, "blocked", self.policy, reason="not admitted"),
                   transition(running, "failed", self.policy, reason="implementation failed"))
        for run in records:
            with self.subTest(state=run.state):
                self.assertEqual(validate_result(encoded(run.to_dict()), self.policy), run.to_dict())

    def test_result_tampering_never_grants_authority(self):
        data = self.completed().to_dict()
        for fields in ({"publishable": True}, {"commit_sha": "f" * 40}, {"ci_results": ["passed"]},
                       {"branch": "master"}, {"policy_digest": "f" * 64}, {"state": "unknown"},
                       {"state": []}, {"reason": "unexpected"}, {"scope_violations": ["blocked"]},
                       {"tests": []}, {"candidate_digest": None}, {"repair_attempts": 3},
                       {"changed_files": []}, {"unexpected": True}):
            with self.subTest(fields=fields), self.assertRaises(Rejected):
                validate_result(encoded(data | fields), self.policy)

    def test_result_rejects_protected_change_unsafe_mode_and_stale_observation(self):
        data = self.completed().to_dict()
        for change in ({"path": ".github/codex/task-policy.json", "operation": "add",
                        "old_mode": None, "new_mode": "100644"},
                       {"path": "tests/test_example.py", "operation": "add",
                        "old_mode": None, "new_mode": "120000"}):
            with self.subTest(change=change), self.assertRaises(Rejected):
                validate_result(encoded(data | {"changed_files": [change]}), self.policy)
        checks = data["tests"]
        checks[0]["candidate_digest"] = "f" * 64
        with self.assertRaises(Rejected):
            validate_result(encoded(data), self.policy)

    def test_schema_fields_states_and_capabilities_match_runtime(self):
        schema = json.loads((ROOT / ".github/codex/task-result.schema.json").read_text())
        self.assertEqual(set(schema["required"]), set(self.completed().to_dict()))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["properties"]["state"]["enum"]), {s.value for s in State})
        self.assertEqual(schema["properties"]["publishable"], {"const": False})
        task_schema = json.loads((ROOT / ".github/codex/task.schema.json").read_text())
        self.assertEqual(set(task_schema["required"]), set(self.payload))

    def test_result_wrong_types_fail_as_rejected_data(self):
        data = self.completed().to_dict()
        for field in ("changed_files", "tests", "limitations", "scope_violations"):
            for value in (None, "not an array", {}):
                with self.subTest(field=field, value=value), self.assertRaises(Rejected):
                    validate_result(encoded(data | {field: value}), self.policy)
        bad = {"path": "tests/test_example.py", "operation": "add", "old_mode": None,
               "new_mode": []}
        with self.assertRaises(Rejected):
            validate_result(encoded(data | {"changed_files": [bad]}), self.policy)

    def test_failed_state_cannot_replace_failure_evidence(self):
        run = self.validating()
        with self.assertRaises(Rejected):
            transition(run, "failed", self.policy, reason="failed",
                       candidate=self.candidate())

    def test_scope_failure_can_enter_repair_without_claiming_tests_executed(self):
        run = self.validating(self.candidate(after={"tests/unrelated.py": file()}))
        repaired = transition(run, "repairing", self.policy)
        self.assertEqual(repaired.checks, ())
        validate_result(encoded(repaired.to_dict()), self.policy)

    def test_nonexecuted_check_cannot_claim_test_counts(self):
        check = Check("python-suite", "blocked", None, self.candidate().digest, 1, 1, 0, 0, 0)
        with self.assertRaises(Rejected):
            check.validate()

    def test_candidate_keeps_unrelated_unchanged_files_out_of_changes(self):
        before = {"nightrecon/scope.py": file(b"unchanged")}
        after = before | {"tests/test_example.py": file()}
        report = self.candidate(before, after)
        self.assertTrue(report.scope_valid)
        self.assertEqual([c.path for c in report.changes], ["tests/test_example.py"])

    def test_only_exact_policy_listed_platform_skips_can_pass(self):
        run = self.validating()
        checks = list(self.passing(run.candidate))
        checks[0] = replace(checks[0], tests_run=2, passed=1, skipped=1,
                            skip_ids=(self.policy.allowed_skip_ids[0],))
        completed = transition(run, "completed", self.policy, checks=tuple(checks))
        validate_result(encoded(completed.to_dict()), self.policy)
        checks[0] = replace(checks[0], skip_ids=("test_unknown.Test.test_unknown",))
        with self.assertRaises(Rejected):
            transition(run, "completed", self.policy, checks=tuple(checks))


if __name__ == "__main__":
    unittest.main()
