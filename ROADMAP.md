# NightRecon Development Roadmap

NightRecon is being developed as an authorization-first adversarial security validation platform for reconnaissance, penetration testing, attack-path analysis, defensive-control validation, and controlled cyber-range operations.

This roadmap is directional. Release scope may be split into smaller verified increments when that reduces risk. Every release must preserve the authorization boundary, avoid unrelated refactors, pass the full automated test matrix, and leave `master` at a stable checkpoint before the next development branch begins.

## Operating Modes

NightRecon will converge on four controlled operational modes, with Purple workflows linking offensive actions to defensive detections.

- **Red** — reconnaissance, exposure discovery, vulnerability validation, attack-path validation, and controlled adversary emulation.
- **Blue** — defensive-control testing, telemetry validation, detection engineering, exposure reduction, and remediation verification.
- **White** — authorization, scope, rules of engagement, approvals, safety controls, audit, evidence, exercise control, and emergency stop.
- **Black** — deliberately knowledge-limited external assessment beginning from an explicitly authorized starting scope.
- **Purple workflow** — correlation of Red actions with Blue prevention, telemetry, alerts, and detection coverage.

## Locked Safety Principles

1. Network and application activity must pass explicit target validation and authorization before execution.
2. Passive is the default. Safe-active behavior must be explicit, bounded, and non-destructive.
3. Intrusive or higher-impact validation belongs behind separate approval-gated workflows rather than ordinary scan flags.
4. Destructive behavior is never part of routine scanning. Future destructive training must remain isolated to explicit cyber-range or simulation contexts.
5. Secrets and live session material remain ephemeral wherever possible and must not enter reports, normal audit output, or CLI output.
6. Findings remain evidence-based. Vulnerability or threat-intelligence matches do not automatically become exploitability claims.
7. Every release must be testable, reviewable, reversible, and independently useful.

## Generation 1 — Complete the Assessment Foundation

### v0.24.0 — Ephemeral Authenticated Session Continuity

Status: release candidate.

- opt-in in-memory session cookie continuity
- same session context reused across authorized same-origin crawl requests
- safe-active OPTIONS probes reuse the same transient session
- session state excluded from persisted crawl results, reports, audit records, and CLI output
- raw cookie-header mode remains mutually exclusive with session-cookie mode
- existing scope, redirect, request-count, and intrusiveness controls remain unchanged

Release gate: documentation complete, full cross-platform CI green, merge to `master`, stable checkpoint verified.

### v0.25.x — Stateful Web Workflow Engine

Goal: represent and safely navigate authenticated application workflows rather than isolated pages.

Planned capabilities:

- explicit workflow model and navigation state
- form-aware discovery without automatic unsafe submission
- CSRF/token observation and bounded replay support where explicitly permitted
- multi-step authenticated flows
- deterministic request budgets
- same-origin and scope revalidation at every transition
- secret redaction and transient credential/session context
- workflow evidence and reproducible traces

### v0.26.x — Browser-Powered Application Discovery

Goal: reach modern JavaScript-heavy applications while preserving NightRecon safety controls.

Planned capabilities:

- sandboxed browser worker
- DOM and SPA route discovery
- client-side navigation observation
- bounded JavaScript execution
- browser request interception and scope enforcement
- browser-worker isolation and resource ceilings
- no automatic high-impact actions

### v0.27.x — API Intelligence

Goal: make APIs first-class assessment targets.

Planned capabilities:

- OpenAPI/Swagger import and discovery
- REST endpoint and schema modelling
- GraphQL metadata/introspection handling when explicitly permitted
- API authentication context
- parameter/type-aware passive checks
- request generation bounded by declared schemas and safety policy
- machine-readable API findings

### v0.28.x — Expanded Safe-Active DAST

Goal: broaden evidence-backed web and API validation without turning routine assessment into exploitation.

Planned capabilities:

- larger deterministic check library
- request budgets per check/family
- response-difference analysis
- explicit intrusiveness metadata
- reproducible evidence
- false-positive reduction
- safe re-test support

### v0.29–v0.30 — Credentialed Infrastructure Assessment

Goal: extend beyond unauthenticated service observation.

Planned targets:

- SSH
- SMB
- WinRM
- supported databases
- supported network devices

Controls:

- explicit credential source
- least-privilege guidance
- read-only/configuration-audit defaults
- secret redaction
- command allowlists
- capability-specific request/action ceilings

## Generation 2 — Identity and Attack-Path Intelligence

Goal: move from isolated findings to graph-based exposure reasoning.

Planned capabilities:

- unified asset/service/identity/permission/vulnerability graph
- Active Directory and Entra ID collection
- group and nested-group relationships
- local-admin and delegated privilege relationships
- service accounts and machine identities
- certificate and trust relationships
- cloud and repository identities
- critical-asset classification
- choke-point and blast-radius analysis
- evidence-backed attack-path search

NightRecon must distinguish observed relationships from inferred hypotheses and keep path reasoning reproducible.

## Generation 3 — Red Validation Engine

Goal: controlled validation of authorized attack paths.

Execution model:

`observation -> hypothesis -> authorization/approval -> isolated validation -> evidence -> cleanup`

Planned capabilities:

- ATT&CK-mapped playbooks
- bounded exploitability validation
- controlled privilege-escalation validation
- controlled lateral-movement validation
- credential-access simulations
- persistence simulations in explicit training/range contexts
- precondition/postcondition reasoning
- automatic cleanup where supported
- action budgets and rate limits
- approval gates and kill switch
- isolated workers with revocable execution capability

High-impact actions must never be exposed as ordinary scan options.

## Generation 4 — Blue Defensive Validation

Goal: test whether defensive controls actually prevent or detect approved activity.

Planned integrations and capabilities:

- SIEM
- EDR/XDR
- NDR
- WAF
- firewall
- IDS/IPS
- cloud security telemetry
- ATT&CK coverage maps
- Sigma rule validation
- detection regression tests
- expected-telemetry definitions
- prevention vs detection classification
- detection-latency measurement
- false-negative tracking
- remediation and re-test loops

Purple workflows will correlate approved Red activity with Blue telemetry and detections.

## Generation 5 — White Team Command Layer

Goal: make authorization and exercise control a first-class product capability.

Planned capabilities:

- engagements and projects
- authorization records
- target allowlists and exclusions
- testing windows
- allowed techniques
- maximum intrusiveness
- approval chains
- request/action budgets
- worker permissions
- encrypted credential/secrets handling
- immutable audit evidence
- exercise control and scoring
- emergency stop and worker revocation
- data-retention policy
- evidence custody and export

The White layer becomes the authority that decides what NightRecon is permitted to execute.

## Generation 6 — Black-Box / External Attack Surface

Goal: assess an organization from an explicitly authorized low-knowledge external starting point.

Planned capabilities:

- domains and subdomains
- DNS and certificates
- external IPs and ASNs
- exposed cloud services
- web applications and APIs
- exposed repositories and public artifacts
- service fingerprinting
- shadow infrastructure
- externally visible vulnerabilities
- change tracking
- provenance showing why each discovered asset is associated with the authorized organization

## Platform and Product Layer

The engine will eventually require a production platform around it:

- REST API
- web UI
- projects and engagements
- RBAC
- encrypted secrets
- distributed workers and job queues
- scheduler
- webhooks and integrations
- evidence viewer
- remediation workflows
- HTML, PDF, CSV, SARIF, and JSON exports
- signed update feeds
- health monitoring
- containerized deployment
- offline/self-hosted operation
- backup/restore
- performance and regression benchmarking
- multi-tenant architecture only after the single-tenant security model is proven

## Immediate Sequence

The current locked execution order is:

1. Finish and release v0.24.0.
2. Verify `master` and CI as a stable checkpoint.
3. Start v0.25.x Stateful Web Workflow Engine in a fresh development branch.
4. Do not begin browser-powered discovery, API intelligence, credentialed infrastructure, identity graphing, or adversary validation until the preceding layer has a verified checkpoint.
