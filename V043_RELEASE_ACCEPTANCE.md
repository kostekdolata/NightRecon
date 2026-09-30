# Red Night v0.43.0 Release Acceptance

This document records the release-specific acceptance boundary for Red Night
v0.43.0 Controlled Validation Intelligence.

Passing this gate means the v0.43 milestone is internally coherent, packaged,
authorization-bound, deterministic, evidence-honest, and stable. It does not
mean every broader Red completion category in `RED_ACCEPTANCE.md` is closed.

## Release target

- `nightrecon-red-night==0.43.0`
- `nightrecon-red-engine==0.43.0`
- `nightrecon-shared-core==0.43.0`

The legacy `nightrecon==0.31.0` distribution remains the compatibility bridge
and pins the matching Red engine/shared core.

## Integrated v0.43 train

1. reviewed validation technique registry
2. exact candidate-to-technique eligibility planning
3. immutable adapter precondition/postcondition contracts
4. isolated revocable worker execution for reviewed read-only proofs
5. durable validation/cleanup evidence with deterministic remediation/retest
6. reviewed ATT&CK relationships and controlled comparison labs

## Execution acceptance

Live v0.43 execution is limited to the reviewed bounded read-only proof set:
TCP selected-service connection proof, TLS transport/exact pre-observed
certificate-fingerprint proof, and HTTP `HEAD /` response-policy proof.

Every invocation requires explicit operator selection, independently authorizes
`validation.run` with one consumed action, runs in a fresh spawned child,
continuously rechecks active engagement/revocation/window/capability/scope/
approval/budget state, enforces hard runtime/I/O/result ceilings, and accepts
evidence only after reviewed postconditions pass.

No generic shell, command, script, SQL, credential, payload, or arbitrary HTTP
request surface is exposed.

## Evidence, cleanup, and retest acceptance

Every worker result becomes deterministic durable `validation.worker-result`
evidence paired with `validation.cleanup` evidence. Current techniques declare
no side effects, so cleanup is `not-required` with zero cleanup actions.

Only exact persisted lifecycle records may drive remediation state:
`not-confirmed` -> `verified`, `confirmed` -> `regressed`, while
denied/revoked/timed-out/contract-rejected/error remains inconclusive.

## ATT&CK and comparison acceptance

Every current validation technique has one explicit ATT&CK review disposition.
The selected-service TCP proof is related to T1046 Network Service Discovery
without claiming complete T1046 implementation. TLS and HTTP policy proofs are
reviewed-unmapped.

The deterministic controlled comparison lab records expected/matched/missed/
invented validation scenarios, evidence shape, cleanup state, ATT&CK review
metadata, operator steps, runtime, and a deterministic fingerprint. Fixture
matching does not establish specialist-product parity.

## Release-quality gate

Before the stable v0.43.0 tag may be created:

1. all three Red distributions and dependency pins are exactly 0.43.0;
2. legacy `nightrecon` remains 0.31.0 with matching 0.43 Red pins;
3. deterministic unit and integrated v0.43 release-acceptance tests pass;
4. isolated and combined wheel smoke passes on Ubuntu/Windows, Python 3.11/3.14;
5. v0.42 exposure plus all v0.43 eligibility/contract/worker/lifecycle/ATT&CK
   runtime jobs pass;
6. the complete CI matrix passes on the exact finalization head;
7. the finalization PR merges to `master`;
8. the exact release merge commit passes the complete CI matrix again;
9. the guarded allowlist binds `v0.43.0` to that immutable release commit;
10. Release Tag Guard creates the annotated tag without moving any existing tag.

## Explicit limitations

v0.43 does not add unrestricted exploitation, arbitrary command execution,
credential harvesting, password spraying, cloud/directory writes, persistence,
privilege changes, autonomous lateral movement, arbitrary request payloads, or
autonomous technique selection.

Live authorized specialist comparisons, broader relationship/discovery
coverage, and professional multi-operator reporting remain broader Red
acceptance work.
