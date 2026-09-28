# Red Night v0.40.0 Release Notes

Red Night v0.40.0 closes the first integrated Red product release train. It is
the first stable release in which the dedicated Red application, Red engine, and
mandatory shared authorization core are versioned together as 0.40.0.

## Delivered

- independent Red Night application and runtime boundary
- persistent engagement workspace with explicit scope, validity windows,
  capability allowlists, action budgets, approval rules, revocation, and audit
- authorization-first read-only identity collection contract
- approval-gated controlled validation contract with secret-free evidence
- unified evidence-backed graph across assets, identities, groups, services,
  vulnerabilities, findings, cloud resources, and critical assets
- policy-constrained plan-only Red operator
- persistent remediation and controlled retest lifecycle
- cryptographically verified Red Checks ecosystem policy and searchable catalog
- authorization-first AWS/Azure/Entra/Kubernetes normalized evidence boundary
- deterministic stack-wide acceptance proving the v0.33-v0.40 components work
  coherently and persist correctly
- standalone/combined wheel smoke coverage plus the existing cross-platform
  runtime compatibility matrix

## Versioning and compatibility

The stable Red distributions are:

- `nightrecon-red-night==0.40.0`
- `nightrecon-red-engine==0.40.0`
- `nightrecon-shared-core==0.40.0`

The legacy `nightrecon` compatibility package remains at 0.31.0 by design
during the migration window. It pins the stable 0.40 Red engine and shared core;
its version is not the Red application version.

## Safety boundary

v0.40 does not introduce exploit payloads, credential harvesting, arbitrary
command execution, cloud writes, persistence mechanisms, privilege changes, or
autonomous execution. Read-only collection and controlled validation remain
subject to explicit scope, authorization, approval, action-budget, evidence, and
audit rules.

## Known open completion gates

The broader Red completion standard remains open for measured specialist
comparison labs, concrete authorized live provider adapters, a reviewed
controlled-validation technique library, expanded professional reporting and
collaboration workflows, and removal of remaining legacy compatibility seams.

See `RED_ACCEPTANCE.md` for the measurable completion standard and
`V040_RELEASE_ACCEPTANCE.md` for the deterministic v0.40 stack acceptance.
