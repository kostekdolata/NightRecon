# Red Night v0.42.0 Release Notes

Red Night v0.42.0 is the Cross-Domain Exposure Intelligence release.

It builds on the v0.41 live AD/Entra identity foundation and connects network,
web/API, identity, cloud/hybrid, critical-asset, remediation, and retest
evidence through deterministic exact correlation and bounded path review.

## Cross-domain attack-path atlas

- bounded directed paths from identity/group/asset/service starts to critical assets
- one global exploration budget
- deterministic path identifiers and ordering
- explicit observed and inferred hop counts
- retained supporting evidence/provenance
- deterministic node/edge participation counts
- explicit depth/path/start/target/expansion truncation

## Exact cross-surface correlation

### AD to network

- exact observed AD DNS/SPN host evidence to observed network asset hostname
- ambiguous/no-match evidence remains unresolved
- no label or fuzzy joins

### Web/API to network service

- web, API, and GraphQL HTTP(S) origins retain exact normalized host/port evidence
- hostname or IP-literal origin must identify one observed network asset
- exact observed TCP service on the origin port is required
- no protocol or service guessing

### Cloud/hybrid

- strict provider-specific AWS/Azure/Entra/Kubernetes correlation-property allowlists
- canonical IP and hostname validation
- exact cloud-resource to observed network-asset correlation
- exact Azure/Entra tenant + Microsoft Graph object-ID identity correlation
- conflicting exact network evidence fails closed
- no DNS resolution, display-name matching, IP adjacency inference, or provider guessing

## Proposal-only validation candidates

Evidence-backed atlas paths can be compiled into deterministic bounded
validation candidates.

Candidates preserve exact path/evidence context but cannot execute. They declare
the required `validation.run` capability, approval review, scope review, and
`proposal-only` execution mode. Any later validation remains subject to the
normal authorization, action-budget, approval, revocation, and audit boundary.

## Exposure review and remediation/retest context

- observed/inferred hop summaries
- inferred-path and unresolved-correlation evidence gaps
- remediation/retest status counts
- descriptive node/edge structural concentration
- unique start/critical-target participation
- before/after path-set comparison

None of these measurements is a risk score or exploitability ranking.

## Comparison/runtime gate

The release adds a deterministic fixture-based comparison harness measuring:

- missed and invented paths
- missed and invented graph edges
- evidence completeness
- runtime
- operator-step count
- truncation

The harness is deliberately not a specialist-product parity claim.

## Versioning and compatibility

Stable Red distributions:

- `nightrecon-red-night==0.42.0`
- `nightrecon-red-engine==0.42.0`
- `nightrecon-shared-core==0.42.0`

The legacy `nightrecon==0.31.0` package remains a compatibility bridge and
pins the matching v0.42 Red engine/shared core.

## Safety boundary

v0.42 does not add:

- automatic exploitation
- arbitrary shell/PowerShell/SQL execution
- password spraying or guessing
- credential harvesting
- cloud or directory mutation
- persistence
- privilege changes
- autonomous lateral movement
- automatic validation execution

Correlation, paths, candidates, concentration counts, and comparison results are
evidence-review objects only.

## Known open completion gates

The broader Red completion standard still requires additional live authorized
specialist comparison, broader relationship/ACL coverage, discovery
false-positive/performance baselines, professional collaboration/reporting, and
reviewed controlled-validation technique coverage.

See `RED_ACCEPTANCE.md` for the broader completion standard and
`V042_RELEASE_ACCEPTANCE.md` for the exact release gate.
