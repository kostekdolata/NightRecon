# Red Night v0.42.0 Release Acceptance

This document records the release-specific acceptance boundary for Red Night
v0.42.0 Cross-Domain Exposure Intelligence.

Passing this gate means the v0.42 milestone is internally coherent, packaged,
deterministic, evidence-honest, and stable. It does not mean every broader Red
completion category in `RED_ACCEPTANCE.md` is closed.

## Release target

The coordinated release consists of:

- `nightrecon-red-night==0.42.0`
- `nightrecon-red-engine==0.42.0`
- `nightrecon-shared-core==0.42.0`

The legacy `nightrecon==0.31.0` distribution remains the compatibility bridge
and pins the matching Red engine/shared core.

## Integrated v0.42 train

The stable milestone includes:

1. Cross-Domain Attack Path Atlas
2. exact AD identity/network correlation
3. exact web/API origin/network-service correlation
4. strict cloud correlation evidence contract
5. exact cloud/network and Azure/Entra identity correlation
6. proposal-only controlled-validation candidate compilation
7. unified exposure review, remediation/retest path-set review, structural
   concentration, and reproducible comparison/runtime metrics

## Correlation acceptance

Cross-surface correlation is deterministic and exact-evidence-only.

The engine does not:

- perform DNS resolution for joins
- use fuzzy, suffix, display-name, IP-adjacency, or provider-guessing joins
- invent missing endpoints
- select one candidate from an ambiguous match
- convert correlation into an authentication, compromise, or exploitability claim

Ambiguous, conflicting, incomplete, or over-budget correlation remains
unresolved or fails closed.

## Validation-candidate acceptance

Validation candidates are review artifacts only.

Candidate compilation:

- preserves exact atlas path, node, edge, and evidence identifiers
- preserves observed/inferred hop counts
- declares `validation.run` as the required capability
- requires scope review and approval review
- uses `execution_mode=proposal-only`
- never calls a validation adapter
- never resolves credentials
- never consumes action budget
- never mutates engagement state

Any later controlled validation must independently pass the existing workspace
authorization boundary.

## Exposure-review acceptance

The v0.42 review surface reports:

- path evidence and observed/inferred hop counts
- unresolved correlation and inferred-path evidence gaps
- remediation and retest state
- node/edge path participation
- unique start and critical-target participation counts
- before/after path-set changes

These are descriptive structural measurements, not risk scores, priorities,
probabilities, causal remediation claims, or exploitability verdicts.

## Comparison/runtime acceptance

The deterministic fixture comparison records:

- expected/matched/missed/invented paths
- expected/matched/missed/invented graph edges
- evidence-complete/incomplete paths
- runtime
- documented operator-step count
- atlas truncation

The fixture gate is a regression and measurement tool. It does not establish
parity with an external specialist product.

## Release-quality gate

Before the stable v0.42.0 tag may be created:

1. all three Red distributions and dependency pins must be exactly 0.42.0;
2. the legacy compatibility distribution must remain 0.31.0 and pin the matching
   0.42 Red engine/shared core;
3. deterministic unit and release-acceptance tests must pass;
4. isolated and combined Red Night wheel installation smoke must pass on Ubuntu
   and Windows for Python 3.11 and 3.14;
5. AD/Entra, attack-path atlas, cross-surface correlation, and v0.42 exposure
   intelligence runtime jobs must pass;
6. the complete CI matrix must pass on the exact finalization head;
7. the finalization PR must merge to `master`;
8. the exact merge commit must pass the complete CI matrix again;
9. the guarded release-tag allowlist must bind `v0.42.0` to that verified
   immutable release commit;
10. Release Tag Guard must create the annotated tag without moving any existing
    tag.

## Explicit limitations

v0.42 does not add automatic exploitation, arbitrary command execution,
credential harvesting, password spraying, cloud/directory writes, persistence,
privilege changes, autonomous lateral movement, or autonomous validation.

Live authorized specialist-product comparison, broader relationship coverage,
professional multi-operator reporting, and a reviewed controlled-validation
technique library remain broader Red acceptance work.
