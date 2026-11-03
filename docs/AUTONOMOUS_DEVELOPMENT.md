# Objective-level development controller — disabled deployment

## Current implementation and operational status

The original Batch 1 primitives below are reused, not replaced. The dependent
objective layers now provide signed approvals, durable authenticated state,
candidate collection, bounded multi-batch orchestration, independent validation
receipts and a credential-broker GitHub API gateway. **This deployment is not
operational.** No live coding/validation service, GitHub transport, owner key,
validator key, publisher credential or release signer has been configured. No
Issue or schedule starts coding. No live push/merge/release rehearsal has run.

The GitHub gateway implements the documented Git objects, ref, PR, effective
branch-rule, check-run, normal protected merge, release and asset APIs through
an injected `GitHubTransport`. There is no default HTTP client or token lookup.
The transport must live in a separate publisher broker; it must map a missing
resource to `None`, sanitize API errors, restrict hosts/paths, verify HTTPS,
honor rate limits, and never return tokens. The coding/validation adapters are
explicit service protocols, not an implemented or activated Codex launcher or
CI dispatch bridge. Unit tests use simulated adapters, never real Codex/GitHub.

Existing CI is reused: its normal discovery includes the new offline tests;
manual CI dispatch and `codex/task-*` push filtering are added. The existing
scheduler retains read-only permissions and its legacy branch/PR readiness
checks, plus a disabled-objective-gate summary. No coding trigger is added.
Release workflows and the release tag allowlist are unchanged.

| Layer | Implementation |
| --- | --- |
| Task, policy, scope, evaluation state | `controller.py` |
| Ed25519 objective, validation and release verification | `objectives.py` |
| SQLite queue, fenced leases, HMAC event chain, artifacts | `queue.py` |
| Read-only pinned Git/working-tree inventories | `inventory.py` |
| Incremental batches, repairs, budgets, publication intents | `service.py` |
| Credential-broker GitHub API operations | `github_gateway.py` |
| Offline signed enqueue and authenticated report CLI | `__main__.py` |

All paths above are under `tools/task_automation/`. The objective layers use the
project's existing cryptography dependency; the original core remains stdlib-only.

## Objective approval and durable queue

The owner approves one immutable objective snapshot, not each incremental batch.
The signed payload includes owner/repository identity, canonical bounded task,
policy digest, approval/expiry timestamps, release permissions, and maxima for
batches, repairs, attempts, wall time, tokens and cost in integer micro-USD.
`.github/codex/objective-approval.schema.json` describes the envelope. Only
explicitly allowlisted owner keys and the `owner` signing role are accepted.

Sign canonical sorted compact JSON with Ed25519, prefixed with the exact domain
`nightrecon-objective-approval-v1` followed by one NUL byte. `verify_approval`
checks the signature, role, owner, scope, base, limits, policy and lifetime.
The owner signing key must stay outside repository, agent and validator hosts.
The trusted public-key registry is protected service configuration, never an
Issue field or candidate file. A different objective or changed approval needs
a new owner-signed revision. Existing objective ID/different snapshot is rejected.
Safety/control-plane changes are rejected even in signed ordinary objectives;
they require a separately reviewed infrastructure-development path.

`ObjectiveQueue` stores immutable approval bytes and append-only execution events.
Every event authenticates its full state, version and predecessor using an
external service HMAC key. SQLite transactions provide exclusive claims and
optimistic versions; leases have monotonically increasing fencing generations.
Stale workers cannot publish a new queue state. Artifact bytes are content-addressed
and rehashed on retrieval. A changed database row, event chain or artifact fails
closed. Database parents, backups and the integrity key require private service
storage. Windows ACLs need separate deployment verification; mode bits are not ACLs.

Budgets reserve a worst-case allowance BEFORE each planning/implementation call,
including the associated validation allowance. Reservations never silently reset
or refund, and counters cannot decrease. A provider/proxy must enforce the actual
token/cost ceiling; the controller does not claim a CLI timeout stops a remote
Cloud task. The wall deadline and leases block late effects. Long-running adapters
need a separately implemented heartbeat/polling bridge; current synchronous
calls block if they overrun the lease. Unknown adapter outcomes are not retried as
successful work. Expiry is persisted by the recovery poll.

Plans must cover all approved acceptance criteria and cannot add new criteria or
command fields. They are frozen in authenticated history. Every batch uses the
same derived objective branch and chains to the previous verified commit. Source
scope is always checked cumulatively against the original base and approval.
An executed, independently signed test failure can enter bounded repair;
missing platforms/checks, bad signatures or infrastructure gaps block instead.
Repairs cannot touch files outside the preceding failing incremental change.
Any repaired candidate receives complete fresh validation before publication.

Each irreversible operation has a durable write-ahead intent. A timeout or crash
with an outstanding commit/push/merge/release intent requires remote reconciliation;
it never causes a blind duplicate operation. A partially completed objective
does not replay prior committed batches. Between completed batches, recovery
restores authenticated frozen bytes, reverifies the receipt and remote head/tree,
and continues the frozen plan at the next batch. Ambiguous publication intents
and post-merge/release interruptions still require operator reconciliation;
safely blocking preserves the signed approval, plan, candidates, receipts,
parent chain and logs for inspection.

## Independent validation and credential separation

Independent validators sign candidate/approval/policy/parent/batch-bound receipts
with the `validator` role. A coding identity cannot use an owner/worker key as a
validator key. The receipt must attest all four Linux/Windows Python 3.11/3.14
platforms and all policy-required checks. Test counts and exit codes are validated;
unexpected skipped tests fail. Only the exact benign platform-specific skip IDs
listed in the protected policy can be accepted, with matching counts. These cover
existing POSIX-only checks and descriptor-collector tests that run on the POSIX
controller host. No wildcard skip is permitted. Signed fixture claims in unit
tests do not establish real cross-platform CI results.

The implementation agent must run in its own disposable sandbox with no queue
integrity key, validator signer or publisher token. Validation runs on fresh
runners from frozen candidate bytes, without model or publishing credentials.
Only a final broker can access a short-lived GitHub App token. Separate Python
objects are NOT an operating-system or credential boundary: these adapters must
be separately sandboxed services before live use.

At the broker boundary the gateway reverifies the signed validation envelope,
candidate digest and full base inventory. GitHub tree contents must exactly
match the independently validated inventory before a commit object is created.
It refuses a pre-existing first-batch branch, unexpected later parent, changed
artifact, absent receipt, missing deployment capability or reserved PR #160.
It never updates master refs or uses force. Publisher errors after an uncertain
side effect stay blocked with their intent retained.

Merge requires signed objective acceptance, every configured CI context and
effective protected-branch context successful for the exact head SHA from the
trusted Actions App. It then calls the normal GitHub merge API. Required reviews,
merge queues, signatures, freshness and other GitHub rules remain authoritative.
The service does not approve its own PRs, modify rules, use admin bypass, or
fabricate missing contexts. Review/rule refusals are reported as blockers.

Live capabilities require a separately owner-signed deployment acceptance
envelope including security signoff, expiry and a harmless end-to-end run URL
and evidence digest. The gateway independently reverifies that signature.
No such real envelope is provisioned. The initial supervised rehearsal must be
owner-operated; a synthetic unit-test envelope is not production acceptance.

## Explicit release objectives

Default release permission is false. A release objective must sign the exact
version tag, artifact basenames and accepted release signer key IDs. After
protected merge, the separate signer/builder supplies an Ed25519 manifest binding
approval, source merge SHA, artifact SHA-256s, SBOM and release-integrity acceptance.
The gateway verifies actual bytes and the SBOM, reads the existing master release
allowlist, and requires the existing approved tag to resolve to the merge SHA.
It does not create or move tags. Existing `release-tags.yml` owns that process.

Only then may the broker create a draft release, upload exact artifacts, verify
GitHub's acknowledged asset digests and publish it. Existing releases are never
overwritten. Interrupted releases require reconciliation. Until the external
builder/signer, signing-key policy and release rehearsal are accepted, release
objectives block before implementation; no live signing credentials are granted.

## Submitting future objectives (offline preparation only)

1. Create a Development objective Issue with one bounded goal, criteria, precise
   paths, resource maxima and an optional release request. This is a proposal.
2. On a trusted owner system, review and construct the complete approval payload
   using the actual Issue number and protected policy revision. Sign the envelope
   using the owner-controlled signer, not code from an untrusted candidate.
3. Submit the signed envelope to the private queue. Its integrity key and trusted
   owner registry must be supplied by protected service configuration. The CLI
   exposes only `enqueue` and `report`; it cannot execute code or publish:

```bash
python -m tools.task_automation \
  --policy /trusted/control/task-policy.json \
  --policy-sha256 <independently-pinned-sha256> \
  --database /private/controller/queue.sqlite \
  --integrity-key-file /private/controller/queue.key \
  enqueue --approval /private/objective-approved.json \
  --owner-trust /private/controller/owner-public-keys.json
```

The owner registry maps key IDs to `owner`, `role: "owner"` and
`public_key_base64` (raw 32-byte Ed25519 public key). Never put a private signing
key in that file. `report <objective-id>` reads authenticated state using the
same global arguments. `.github/codex/objective-result.schema.json` describes
service reports: commits, files, tests, CI URLs, resources, blockers and limits.
`operational` remains false in this implementation. Signing a proposal does not
activate the scheduler; no future objectives will execute until deployment gates
and external adapters are accepted.

## Owner actions and remaining live acceptance gates

The owner must verify the exact GitHub master rules and required CI contexts,
App identities and bypass exclusions. In this development environment the
read-only GitHub rules API request returned **Forbidden**; effective rules were
not inspected or altered. Do not infer their contents from repository admin access.

Owner-controlled setup is still required for:

- Private queue storage, backup/recovery and integrity-key management.
- Owner, independent validator and deployment public-key registries and revocation.
- Real coding and independent precommit CI dispatch/receipt adapters, provider-side
  budgets, cancellation and lease heartbeats. Prefer the documented Codex Action
  on a fresh runner; do not assume the experimental Cloud CLI works unattended.
- A separate non-bypass GitHub App broker, protected branches/tags/environments,
  exact required checks and permitted merge method. Required human reviews remain
  required; the objective blocks if they are absent.
- Real Windows/Python matrix evidence and a supervised harmless objective proving
  implementation, full independent tests, commit, push and protected merge.
- Release builder/signing and allowlisted-tag acceptance, only for release objectives.

These are gates within the current controller-development objective, not permission
to start another objective. No code enables unattended operation or grants live
credentials just because an environment variable is set.

## Operating costs

Costs are model usage, runner time, broker/queue hosting and artifact retention.
An objective signs maxima for attempts, tokens, micro-USD and wall seconds; repairs
consume the same allowance. Reserve the worst case and stop on exhaustion.
Public-repository standard GitHub runners may be free under the applicable plan;
private/larger runners and storage have separate costs. Use current provider
rates and measured job usage when configuring reservations; unit-test fixture
costs are not production estimates. Avoid best-of-N task submissions by default.

Development approval never grants real-world target authorization. High-impact
cybersecurity execution still requires the project's separate scope, authorization,
approval and audit controls. The default deployment has no such execution ability.

## Original offline core contracts

The original Batch 1 core supplies offline, deterministic data validation only. It does not watch
Issues, launch Codex, run commands, collect Git snapshots, reserve branches,
contact GitHub, persist queue state, collect CI results, commit, or push. The
core never activates a scheduler or workflow. The limited CI/readiness integration
changes in this objective are described above.

The controller is in `tools/task_automation/controller.py` and uses only the
Python standard library. It is development tooling, not part of a Night product
distribution. No Red engine, application, shared core or dependency metadata is
changed. The implementation of this infrastructure batch is explicitly authorized
development; ordinary future tasks cannot edit these protected controller files.

## Task and policy trust boundary

`.github/ISSUE_TEMPLATE/development-task.yml` is a proposal form, not an execution
trigger. Its JSON textarea contains the task specification without a submitter,
repository role, executable commands, branch override or credentials. A future
adapter must parse the known field, reject unexpected fields, inject the actual
Issue number from verified GitHub metadata, and form the canonical snapshot in
`.github/codex/task.schema.json`. It must not trust a body-supplied Issue number.
There is deliberately no Markdown/Issue-body extraction adapter in this batch.

`parse_task` rejects malformed or oversized JSON, duplicate keys, non-finite
numbers, unknown fields, incorrect primitive types (including booleans as IDs),
empty criteria, unauthorized base commits, invalid operations and unsafe paths.
Issue text is inert text; it is never evaluated or passed to a shell. The
canonical snapshot hash binds task identity to content, revision and base SHA.

`load_policy(raw, expected_digest=...)` requires the SHA-256 of the exact policy
bytes from a trusted source. The caller must obtain that digest from a reviewed,
pinned control revision or protected configuration, never from an Issue,
candidate, sibling sidecar in an untrusted checkout, or test output. Recomputing
the digest of arbitrary candidate policy bytes is not authentication. The
current reviewed policy bytes hash to:

```text
78fa08e5a8e3332de5a73d19c1a8333c725f42705d0dd6db251ee91decdf48a9
```

The policy pins the initial base
`09707e49116b6021fa7bb695c1979aeb240b4fca`. Updating that base or policy is a
separately reviewed control-plane change. The loader additionally refuses enabled
execution/publishing/external assessments, unsafe modes, excessive repair limits,
missing mandatory control protection, and removed baseline validations.

Default limits are 16 KiB per task, 20 changed files, 1 MiB of changed bytes
(old plus new contents), two repair attempts, and a future 60-minute execution
limit. There is no timer/executor in Batch 1; time budgets must eventually be
enforced outside the model. Permitted roots and protected exceptions are explicit
in `task-policy.json`. Protected paths win. A broad task scope overlapping a
protected file is rejected; request precise files or a narrower directory.

`admit` takes an out-of-band `VerifiedIdentity`, actual repository and Issue
identity, observed base SHA and existing branch inventory. The default owner
allowlist also requires `admin` or `maintain` repository permission. A role or
login in the Issue body cannot supply this evidence. All identity objects remain
caller assertions until a future adapter verifies them against GitHub.

Branches are derived, never chosen by task text:

```text
codex/task-<issue>-r<revision>-<first-12-task-hash-characters>
```

Existing branches, including a branch already pointing at the same base, cause
rejection. Branch checks compare case-insensitively and accept full
`refs/heads/` inventory names. This is a pure conflict preflight, not atomic
reservation. The future controller must reserve the branch using compare/create
semantics and never force-push an existing branch. This API does not touch master
or any pre-existing development branch.

## Candidate inventories

`inspect_candidate` accepts COMPLETE base and candidate mappings from repository
paths to frozen `FileEntry(mode, content_bytes)` values. Both mappings are copied
before use. Renames are deletion plus addition. No caller-supplied changed-file
list is accepted. The trusted Git/filesystem collector must include tracked
and untracked additions, modifications, deletions and modes; an omitted entry
cannot be discovered by this pure function. Base bytes must come from the pinned
Git tree. This module does not claim to establish inventory provenance.

Portable paths reject traversal, absolute paths, backslashes, alternate streams,
control/non-ASCII characters, Windows reserved names, trailing dots, `.git`
components and ambiguous separators. Full inventories reject case collisions
and file/symlink ancestor conflicts. Links are opaque bytes, never followed.

For each change the policy checks both task and global scope, protected paths,
explicit operation permission, old/new modes and byte/file limits. Deletion must
be explicitly requested in the task. Symlink, submodule and executable changes
are denied, including deletion of unsafe entries and mode-only changes. Only
regular `100644` changed files are accepted in Batch 1. Empty candidates fail.
Invalid inventories raise `Rejected`; well-formed but disallowed changes produce
deterministic violations. Unchanged unrelated files remain outside the change
list but inside the candidate digest.

The digest binds the full before/after content hashes and modes, task, policy
and base. Evidence for a previous candidate cannot pass validation for a new
candidate. A valid scope check never makes a candidate publishable.

## States and results

Normal evaluation path:

```text
pending -> admitted -> running -> validating -> completed
                                      |
                                      v
                                   repairing -> validating
```

Only `admit` can enter `admitted`; a generic state transition cannot bypass its
identity/base/conflict checks. Active states can terminate as `blocked` or
`failed`, with a required reason. `blocked`, `failed` and `completed` are terminal
for an attempt. A new attempt requires a newly verified admission, not editing a
terminal record. Terminal transitions preserve existing candidate evidence.

`running` represents a proposed state in an offline evaluation; changing a state
does not start a process. Repairs require scope failure or a failed check and
consume the bounded repair counter. Missing dependencies, infrastructure failure
and authorization gaps should terminate as blocked, not be treated as permission
to repair unrelated code. Re-entering validation requires a candidate and clears
all previous checks. Completion requires valid scope, every policy-required
check, matching candidate digests, unique check IDs and no failed, blocked or
unexecuted observations, including extra observations. Test-check counts must be
present and consistent; zero executed tests or non-allowlisted skips are not success.

`Run.to_dict()` emits the machine-readable record described by
`.github/codex/task-result.schema.json`. `validate_result` additionally checks
cross-field and policy invariants, test totals and evidence bindings. The schema
is an interchange contract, not a replacement for runtime semantic validation.
All records have `commit_sha: null`, `publishable: false`, and `ci_results: []`.
`completed` means OFFLINE EVALUATION COMPLETE, not committed or published.
Limitations are included in every record. Check records are structured data;
strings such as "all tests passed" are not accepted as observations. No serialized
record can be imported as authorization to execute or publish.

Python dataclasses, caller-provided identities, inventories and check observations
are not cryptographic capabilities or an adversarial same-process sandbox. The
trusted adapters must independently establish provenance. In particular,
this module cannot establish that a test was genuinely run merely because a
caller constructs a `Check` object.

## Validation plan

The policy requires these named checks; it does not contain shell commands:

| ID | Intended check |
| --- | --- |
| python-suite | Entire `tests/run_tests.py` discovery suite |
| controller-tests | `python -m unittest tests.test_task_automation -v` |
| python-syntax | Parse Python source without generating bytecode |
| dependency-check | `python -m pip check` in the selected environment |
| red-launcher-smoke | `python tests/red_night_package_smoke.py` |
| red-package-boundary | Existing Red package namespace, ownership and runtime-boundary tests |

Batch 1 tests cover malicious task input, unauthorized identities, branch
conflicts, policy pinning/tampering, candidate path and mode violations, stale
evidence, failure/repair transitions and permanent non-publishability. They run
under existing discovery without workflow changes or new dependencies.

The full suite creates local loopback servers and some CLI tests save default
reports. Use an execution sandbox allowing loopback, no external assessment
targets, and disposable result storage. Repository test output is evidence only
after a trusted harness checks exit status, counts and source provenance. The
controller does not parse arbitrary stdout or select a command from Issue text.

## GitHub Actions integration constraints

Reuse `nightrecon-autonomous-scheduler.yml` for admission/reconciliation, retaining
its schedule as a recovery poll and adding trusted Issue and manual events only
in a separately authorized batch. Issues remain the durable queue; GitHub
concurrency is not a FIFO queue. Task edits invalidate snapshots. Unknown remote
submission outcomes must not cause duplicate automatic submissions.

Separate jobs/trust domains will handle admission, implementation, validation
and publication. Run approved controller/workflow code from a pinned control
revision. The agent cannot edit its policy, remove tests, change required checks
or acquire publisher credentials. Candidate tests and build hooks must run with
no model/publishing secrets. Elevated packaging/storage fixtures belong on
separate disposable runners, not in the coding agent's privilege boundary.

Existing CI should become reusable validation jobs over immutable candidates.
All required checks must pass BEFORE an implementation commit is created. Jobs
that assume a committed source revision need candidate/tree provenance support;
unavailable required jobs block completion. Bind each result to the exact
candidate, trusted workflow revision and run. After any repair, rerun the entire
required plan, not just a previously failed test. Test deletion or weakened
coverage needs explicit task authorization and independent review; scope alone
cannot prove preservation of existing functionality.

`openai/codex-action` runs Codex on a GitHub runner, not Codex Cloud. The Cloud
CLI is experimental; unattended authentication, environment compatibility,
complete result retrieval, repair continuation and cancellation must be verified
before enabling a Cloud adapter. Do not invent REST endpoints, assume Issue
mentions start Cloud tasks, or export a personal authentication file to public
CI. No coding adapter is implemented here.

The separately accepted publisher alone may have a short-lived repository write token. Enforce
branch/tag rulesets and expected-parent checks; a contents-write token is not
intrinsically branch-scoped. No direct master-ref push or release-tag changes.
Objective-level merges and release publication use only the protected gates
described above, after their independent deployment acceptance.
Do not assume a `GITHUB_TOKEN` push triggers CI; use reusable jobs or an explicitly
authorized dispatch. A separate result artifact avoids changing the validated
source tree just to record its resulting commit SHA.

Default operation remains offline/fixture-only. Issue text never supplies target
authorization. Real-world intrusive cybersecurity actions require independently
verified target scope and the project's explicit approvals. The controller has
no such action capability.

### Original Batch 2 plan (implemented by the objective layers above)

1. Add a read-only local Git collector binding complete base/candidate inventories
   (including untracked paths, modes and link metadata) to pinned base/tree IDs;
   prevent symlink races, Git config/helper execution, oversized inputs and
   partial collection. No commit, checkout, push or external command from tasks.
2. Add durable local attempt records with atomic compare-and-swap/leases,
   idempotency, terminal-state immutability and crash recovery.
3. Add trusted structured test-result ingestion and candidate-bound validation
   plans, retaining logs without interpreting them as instructions.
4. Test against disposable Git repositories and simulated queue/CI data, including
   conflicting claims, task edits, artifact tampering and interrupted writes.
5. Keep live GitHub integration, Codex execution and publication disabled. Their
   credentials, permissions and workflow activation require later authorization.

No batch activates the scheduled coding workflow. Prove
deterministic provenance and recovery before connecting external services.
