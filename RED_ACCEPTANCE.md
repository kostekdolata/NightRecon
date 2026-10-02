# Red Night Completion Standard

Red Night is intended to be a separately installable, authorization-first
assessment and adversary-validation application. Its existing reconnaissance,
web/API, infrastructure, and graph foundations do not make it a finished Red
product. Completion requires the measurable gates below; no single specialist
product is the definition of parity across every discipline.

Benchmark reviewed on 2026-09-27 against official product documentation:

| Specialist reference | Capability to measure | NightRecon today | Red acceptance gate |
| --- | --- | --- | --- |
| [Nmap](https://nmap.org/book/man.html) | Broad, efficient network discovery and service/OS identification | Bounded TCP reachability, scanning, service/version and evidence-based OS hints | Lab comparison across IPv4/IPv6, TCP and appropriately approved UDP cases, false positives, performance, and scope limits |
| [Burp Scanner](https://portswigger.net/burp/documentation/scanner) and [ZAP](https://www.zaproxy.org/docs/automate/automation-framework/) | Authenticated modern web/API traversal, configurable audit coverage, repeatable automation | Bounded crawl/browser discovery, selected safe checks, OpenAPI/GraphQL inspection and explicit GET/HEAD validation | Authenticated stateful browser and API workflows plus a reviewed check library, with false-positive and safety regression corpora |
| [BloodHound](https://bloodhound.specterops.io/get-started/introduction) | AD/Entra identity relationships and useful paths to critical assets | Authorized bounded AD/Entra collectors, provenance, user/service/computer/application identities, group memberships, ownership, scoped Entra roles, selected AD privilege/delegation/trust relationships, bounded paths, and deterministic no-network benchmark fixtures; live specialist comparison remains open | Authorized collectors, privilege/trust modeling, path explanations, incomplete-evidence handling, and lab validation |
| [Metasploit](https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html) | Reusable validation modules with preconditions and outcomes | Signed checks and read-only infrastructure actions; no exploit validation engine | Controlled, approval-gated validation adapters in isolated workers with evidence, limits, cleanup, and tested failure handling |
| [MITRE Caldera](https://caldera.readthedocs.io/en/5.3.0/) and [ATT&CK](https://attack.mitre.org/resources/adversary-emulation-plans/) | Technique-mapped adversary emulation and reproducible operations | No live emulation operations | ATT&CK-mapped plans, approved execution/simulation, operator stop, cleanup, and evidence that can feed Purple |
| [Cobalt Strike](https://www.cobaltstrike.com/) | Operator collaboration and exercise reports | Structured JSON and audit records; no multi-operator Red workspace | Engagement-level collaboration, evidence review, redacted reports, export, and exercise handoff without requiring an unrestricted agent |

These references set evaluation categories, not a plan to copy every feature or
to claim that a matching feature name means equivalent effectiveness.
Red Night must have a repeatable lab result for every relevant category before
any claim that it matches or exceeds a specialist tool. Measure detection
coverage, false positives, runtime, operator steps, evidence quality, and
authorization behavior under the same documented lab conditions. Unmeasured
categories remain open even when a similar feature exists.

## Release gates

1. **Independent installation:** a Red package and launcher install without
   Blue Night, Purple Night, White Night, or Black Night applications. The mandatory shared safety
   core remains present. An all-editions installation composes without changing
   Red's defaults. Test both the isolated and combined installations.
2. **Engagement safety:** authorization records, explicit target and time scope,
   action budgets, operator approvals for higher-impact activity, revocable
   execution, and non-secret audit evidence are verified end to end.
3. **Discovery depth:** controlled lab comparisons for network, web, API, and
   credentialed inventory record coverage, false positives, performance, and
   why an expected asset or service was missed.
4. **Identity and paths:** AD/Entra and other relevant collectors feed the
   versioned evidence graph. Path review preserves observed versus inferred
   relationships, incomplete results, and provenance. A graph path alone never
   becomes an exploitability verdict.
5. **Controlled validation:** allowlisted techniques have documented
   preconditions, approvals, action limits, cleanup, and evidence. High-impact
   training remains in explicit isolated range/simulation contexts.
6. **Professional output:** findings include reproducible evidence,
   limitations, remediation, retest outcome, and export. Sensitive request or
   credential material does not enter ordinary reports.
7. **Quality gate:** deterministic unit tests, local lab integrations, negative
   authorization tests, packaged-install smoke tests, performance baselines,
   and the full cross-platform CI matrix pass before a release is tagged.

## v0.40 release state

Red Night v0.40.0 is a separately installable, stable versioned milestone built
from three coordinated distributions: `nightrecon-red-night`,
`nightrecon-red-engine`, and the mandatory
`nightrecon-shared-core`. The legacy `nightrecon==0.31.0` distribution
remains a compatibility bridge and is not the Red application package version.

The v0.40 stack-wide acceptance scenario verifies one coherent authorization-
bound engagement across workspace policy, read-only identity evidence,
normalized cloud/hybrid evidence, controlled validation, the unified graph,
plan-only operator decisions, signed-check policy, remediation, retest, audit,
action-budget persistence, and workspace reopening. The acceptance is
deterministic and network-free; provider adapters are fakes while the production
policy, persistence, evidence, graph, planning, remediation, and ecosystem
boundaries are exercised.

The stable v0.40 milestone still does **not** mean every Red completion gate above
is closed. The remaining evidence-backed product work includes specialist
comparison labs, concrete authorized live AD/Entra and cloud adapters behind the
tested read-only contracts, a reviewed controlled-validation technique library,
broader professional reporting/collaboration workflows, and continued removal of
legacy compatibility seams where they remain. Unmeasured categories remain open.

v0.40 does not add exploit payloads, credential harvesting, arbitrary command
execution, cloud write operations, persistence mechanisms, privilege changes, or
autonomous execution. Higher-impact future validation remains subject to the
same explicit authorization, approval, budget, isolation, evidence, cleanup, and
operator-stop requirements.

## v0.41 release state

Red Night v0.41.0 moves the identity gate beyond the v0.40 fake-provider
acceptance baseline with stable concrete AD/Entra provider and operator boundaries.

Implemented and CI-covered work now includes:

- concrete authorization-first read-only Active Directory collection over
  certificate-validating LDAPS or StartTLS
- concrete authorization-first read-only Microsoft Entra collection over a
  fixed Microsoft Graph v1.0 plan
- user, service, computer, application, group, and domain identity evidence
- direct/nested and primary-group membership evidence
- Entra application/service-principal ownership
- scoped Entra directory-role assignments
- selected Active Directory well-known privileged-group semantics
- Active Directory `managedBy` relationships
- constrained-delegation target relationships resolved through observed SPNs
- neutral domain-trust relationships with direction/type/attribute evidence
- explicit incomplete-evidence behavior for missing, ambiguous, ranged,
  redirected, or over-budget observations
- deterministic label-free AD and Entra benchmark fixtures
- authorization-first live operator commands with identity-safe default output

The stable v0.41 milestone closes the concrete AD/Entra identity-provider
foundation and selected relationship-modeling work. It does **not** close the broader Red
completion standard by itself.

Still-open acceptance work includes:

- live authorized comparison labs against specialist identity tooling
- broader ACL/security-descriptor relationship coverage where it can be kept
  read-only, bounded, and evidence-honest
- cross-category discovery performance/false-positive baselines
- broader professional reporting/collaboration workflows
- reviewed controlled-validation coverage and external lab evidence

No v0.41 work changes the rule that a graph path or privilege relationship is
descriptive evidence, not an exploitability verdict.


## v0.42 release state

Red Night v0.42.0 is the Cross-Domain Exposure Intelligence milestone. It
connects previously separate network, web/API, identity, cloud/hybrid,
critical-asset, remediation, and retest evidence through deterministic graph
correlation and bounded path review.

Implemented and CI-covered v0.42 work includes:

- bounded deterministic cross-domain attack-path atlas
- exact AD identity to network-asset correlation
- exact web/API origin to observed network-service correlation
- strict cloud correlation evidence contracts for AWS, Azure, Entra, and Kubernetes
- exact cloud-resource to network-asset and Azure/Entra identity correlation
- proposal-only validation candidates that cannot execute automatically
- unified exposure review with evidence gaps and remediation/retest state
- descriptive path/node/edge concentration and path-set change reporting
- fixture-based comparison/runtime metrics for missed/invented paths and edges,
  evidence completeness, runtime, operator steps, and truncation
- dedicated cross-platform/package and Python 3.11/3.14 quality gates

The stable v0.42 milestone does **not** close the broader Red completion
standard. Live authorized specialist-product comparison, broader
ACL/security-descriptor coverage, broader discovery false-positive/performance
baselines, professional multi-operator reporting, and a reviewed
controlled-validation technique library remain open evidence-backed work.

A path, correlation edge, validation candidate, concentration count, or
fixture-comparison result remains descriptive/review evidence. None of these
objects independently establishes exploitability, compromise, authentication
access, likelihood, impact, risk, or permission to execute.



## v0.43 release state

Red Night v0.43.0 is the stable Controlled Validation Intelligence milestone.
It has a reviewed, evidence-backed validation chain from proposal through
explicit bounded execution, durable lifecycle evidence, retest, and comparison:

- reviewed symbolic technique registry
- exact candidate-to-technique eligibility
- immutable adapter/precondition/postcondition contracts
- explicit operator-selected isolated revocable workers for the current
  read-only proof techniques
- durable validation and cleanup evidence with deterministic remediation/retest
  transitions
- one reviewed ATT&CK relationship: the selected-service TCP proof is related
  to T1046 Network Service Discovery, without claiming full technique
  implementation
- explicit reviewed-unmapped dispositions for the TLS metadata proof and HTTP
  response-policy proof rather than force-fitting ATT&CK IDs
- deterministic fixture comparison across expected/matched/missed/invented
  validation lifecycle scenarios, evidence shape, cleanup state, ATT&CK review
  disposition, operator steps, runtime, and a reproducible comparison
  fingerprint

The stable v0.43 milestone closes the release-specific controlled-validation
chain for the current reviewed read-only proofs, but it does **not** close the
broader Red completion standard. The v0.43 comparison lab remains an internal
deterministic fixture lab and does not establish parity with ATT&CK, Caldera,
Metasploit, Cobalt Strike, Nmap, Burp/ZAP, BloodHound, or another specialist
product. Live authorized specialist comparisons, broader discovery/identity
coverage, and professional multi-operator reporting remain open until measured
under the same documented authorized lab conditions.


## v0.44 deployment development state

Red Night v0.43.0 remains the stable functional baseline while v0.44 develops
deployment parity and production-hardening evidence.

The target remains one Red product with three Red-owned deployment profiles:

- standalone Red installation;
- Red inside a composed NightRecon stack;
- Red Night Live USB.

Verified deployment foundations now include:

- identical mandatory Red/shared-core package identities across standalone,
  composed, and Red-only Live profiles;
- no peer-Night runtime imports from Red app/engine sources;
- clean Red+White normal-install composition, independent removal, and one
  shared engagement/workspace carrying source identity, provenance, and
  limitations without transferring authorization;
- explicit fail-closed Red package-version and shared-schema compatibility;
- reproducible Debian-based amd64 Live image construction and UEFI VM userspace
  boot proof;
- privileged appliance modes with no authorization effect;
- LUKS2 Secure Workspace provisioning/reopen, Ephemeral non-modification,
  safe-close/removal, interrupted-session recovery, and read-only filesystem
  integrity evidence;
- deterministic package integrity manifests and secret-free SBOM metadata;
- Ed25519-signed offline update verification before staging;
- immutable Live retention and verification of the exact Red release wheels;
- bounded update/rollback planning that requires a locked encrypted workspace,
  compatible packages/schema, a verified signed bundle, and a verified rollback
  artifact.

The deployment-readiness contract must remain evidence-honest. Automated CI
success cannot by itself establish:

- Secure Boot on a production signing chain;
- compatibility with representative physical hardware;
- USB/media endurance under long-running and repeated reboot/removal cycles;
- Red+White Live composition before White's own independently versioned Live
  persistence/deployment boundary is accepted.

Those items remain explicit manual/external deployment gates and must be
recorded as blockers until real evidence exists.

Live USB capability is not considered complete merely because the application
starts inside Linux. Red authorization, evidence, isolated validation workers,
cleanup/retest, reporting, persistence, update, and recovery behavior must
retain parity with the normal installation.

