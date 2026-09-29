# Changelog

All notable NightRecon/Red Night release milestones are recorded here.

## [0.42.0] - 2026-09-29

### Red Night

- Added the bounded deterministic Cross-Domain Attack Path Atlas with explicit
  observed/inferred hop counts, provenance, global budgets, and truncation.
- Added exact AD computer/service to network-asset correlation using observed
  DNS/SPN hostname evidence only.
- Added exact web/API/GraphQL origin to observed network-service correlation
  with no DNS resolution, fuzzy matching, or service guessing.
- Added strict provider-specific AWS/Azure/Entra/Kubernetes correlation evidence
  contracts and exact cloud-resource to network-asset correlation.
- Preserved exact Entra tenant/object identifiers for deterministic
  Azure/Entra cloud-identity correlation while keeping graph natural keys opaque.
- Added proposal-only validation candidates compiled from evidence-backed paths;
  candidates never execute adapters, resolve credentials, consume action budget,
  or mutate engagement state.
- Added unified exposure review with evidence gaps, remediation/retest state,
  descriptive structural concentration, and before/after path-set comparison.
- Added fixture-based comparison/runtime metrics for path/edge coverage,
  invented/missed facts, evidence completeness, runtime, and operator steps.
- Added dedicated Python 3.11/3.14 v0.42 exposure-intelligence runtime CI.

### Compatibility

- Versioned `nightrecon-red-night`, `nightrecon-red-engine`, and
  `nightrecon-shared-core` together at 0.42.0.
- Kept the legacy `nightrecon` compatibility distribution at 0.31.0 while
  pinning Red engine/shared-core 0.42.0.
- Preserved isolated Red installation and combined legacy/Red distribution
  smoke coverage on Ubuntu and Windows with Python 3.11 and 3.14.

### Safety

- Cross-surface correlation is exact-evidence-only and fails closed on missing,
  ambiguous, conflicting, or over-budget evidence.
- Validation candidates are proposals only; normal scope, capability, approval,
  action-budget, revocation, and audit checks remain authoritative for any later
  controlled validation.
- Structural path/concentration metrics are descriptive only and do not become
  risk scores, priorities, exploitability, compromise, likelihood, or impact.
- No automatic exploitation, cloud/directory writes, credential harvesting,
  persistence, privilege changes, or autonomous execution were added.

Detailed release notes: [V042_RELEASE_NOTES.md](V042_RELEASE_NOTES.md)

## [0.41.0] - 2026-09-29

### Red Night

- Added concrete authorization-first read-only Active Directory collection over
  certificate-validating LDAPS or StartTLS.
- Added concrete authorization-first Microsoft Entra collection through a
  fixed Microsoft Graph v1.0 plan.
- Added identity-safe live operator commands for AD and Entra collection.
- Added deterministic AD/Entra benchmark fixtures on Python 3.11 and 3.14.
- Added user, service, computer, application, group, role, and domain identity
  evidence under separate AD/Entra namespaces.
- Added direct/nested and primary-group membership evidence.
- Added Entra application/service-principal ownership and scoped directory-role
  assignments.
- Added selected Active Directory privileged-group semantics, group management,
  constrained-delegation targets, and neutral domain-trust relationships.
- Added explicit incomplete-evidence handling for ranged, missing, ambiguous,
  redirected, or over-budget observations.
- Added bounded membership-path review and deterministic graph/report
  fingerprints to the live identity workflow.
- Completed migration/ownership registration for the v0.41 identity-provider
  modules while preserving legacy compatibility facades.

### Compatibility

- Versioned `nightrecon-red-night`, `nightrecon-red-engine`, and
  `nightrecon-shared-core` together at 0.41.0.
- Kept the legacy `nightrecon` compatibility distribution at 0.31.0 while
  pinning Red engine/shared-core 0.41.0.
- Preserved isolated Red installation and combined legacy/Red distribution
  smoke coverage on Ubuntu and Windows with Python 3.11 and 3.14.

### Safety

- Live identity collection remains authorization-first and read-only.
- Default operator output excludes identity labels, raw AD DNs, Entra object
  IDs, password/token values, and credential environment-variable names.
- No arbitrary LDAP/Graph query surface, directory writes, credential
  harvesting, DCSync/replication abuse, Kerberos ticket theft/forging,
  persistence, privilege changes, lateral movement, or autonomous exploitation
  were added.

Detailed release notes: [V041_RELEASE_NOTES.md](V041_RELEASE_NOTES.md)

## [0.40.0] - 2026-09-28

### Red Night

- Stabilized the dedicated Red Night application, Red engine, and shared core at
  version 0.40.0.
- Added engagement lifecycle/workspace policy and persistent authorization audit.
- Added authorization-first read-only identity intelligence.
- Added approval-gated controlled validation.
- Added the unified evidence-backed attack graph.
- Added the policy-constrained plan-only Red operator.
- Added remediation and controlled retest lifecycle.
- Added signed Red Checks ecosystem policy and catalog.
- Added authorization-first normalized cloud/hybrid intelligence boundary.
- Added deterministic stack-wide release acceptance across the v0.33-v0.40
  integration path.

### Compatibility

- Kept the legacy `nightrecon` compatibility distribution at 0.31.0 while
  pinning stable Red engine/shared-core 0.40.0 dependencies.
- Preserved standalone Red installation and combined legacy/Red installation
  smoke coverage.

### Safety

- No exploit payloads, credential harvesting, arbitrary command execution,
  cloud write operations, persistence mechanisms, privilege changes, or
  autonomous execution were added by this release.

Detailed release notes: [V040_RELEASE_NOTES.md](V040_RELEASE_NOTES.md)

Earlier release history remains documented in [ROADMAP.md](ROADMAP.md) and the
guarded annotated tags.
