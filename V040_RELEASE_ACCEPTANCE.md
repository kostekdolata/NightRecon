# v0.40 Stack-wide Release Acceptance

This acceptance slice verifies the corrected v0.33-v0.40 Red Night stack as one
coherent, authorization-bound engagement rather than a collection of isolated
green modules.

The deterministic acceptance scenario is network-free and uses fake provider
adapters, but exercises the production policy, persistence, evidence, graph,
planning, remediation, and check-ecosystem boundaries.

Acceptance chain:

1. Create one active engagement with explicit scope, capability allowlist,
   approval rules, validity window, and action budget.
2. Collect read-only Active Directory identity evidence through the authorized
   provider boundary.
3. Convert that observed identity bundle into portable engagement evidence and
   project memberships into the unified graph.
4. Collect normalized multi-provider cloud evidence through the authorized
   cloud boundary and persist it in the same engagement.
5. Run an approval-gated controlled validation and record the resulting finding
   against an observed asset.
6. Build one unified graph containing local assets, directory identities/groups,
   cloud identities/resources, findings, critical assets, and observed
   relationships.
7. Compile an autonomous plan in plan-only mode, proving allowed steps do not
   consume action budget and out-of-scope proposals remain blocked.
8. Admit a cryptographically pre-verified Red Check through signer,
   intrusiveness, and capability policy.
9. Progress the finding through remediation and run a controlled retest.
10. Close the finding only when the retest returns NOT_CONFIRMED.
11. Reopen the workspace/remediation stores and verify evidence, action budget,
    authorization audit, graph, and remediation state persist consistently.

The identity engagement-evidence bridge is pure and network-free. It does not
add collection capability; it only converts already-observed identity evidence
into the existing portable EvidenceRecord vocabulary.

This acceptance milestone does not add exploit payloads, credential harvesting,
arbitrary command execution, cloud write operations, or autonomous execution.
