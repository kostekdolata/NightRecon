# NightRecon Edition Architecture

NightRecon is planned as five independently selectable editions built on one
authorization-first core. A user should eventually be able to install any one
edition, any combination, or the complete suite without maintaining five copies
of the scanners, evidence models, or safety rules.

| Edition | Product responsibility | Current state |
| --- | --- | --- |
| White | Engagement scope, rules of engagement, approvals, audit, evidence custody, exercise control, and emergency stop | Shared scope/audit foundations exist; standalone edition not available |
| Blue | Defensive telemetry, control validation, detection coverage, and remediation retests | Planned; standalone edition not available |
| Red | Authorized reconnaissance, exposure and attack-path analysis, bounded validation, and controlled emulation | Reconnaissance/assessment/graph foundations exist; standalone edition not available |
| Purple | Match approved Red actions to Blue prevention, alerts, telemetry, and detection gaps | Planned; standalone edition not available |
| Black-box | Authorized outside-in assessment from a deliberately limited starting knowledge set | External reconnaissance foundations exist; standalone edition not available |

`nightrecon editions` (or `nightrecon editions --json`) exposes the current
catalog. It is informational only: it does not select, install, enable, or
authorize an edition. The existing `nightrecon` CLI continues to work as before.

An internal `edition_gateway` now denies unowned commands before calling the
existing CLI. Red can route existing authorized assessment commands through this
boundary. White, Blue, Purple, and Black-box expose only the informational
catalog there for now. In particular, the generic CIDR discovery command is not
silently presented as a Black-box external-assessment workflow. The gateway is
not yet an installed application or a substitute for the core scope checks.

## Separation contract

- The shared core owns existing scope and authorization checks, budgets, secret
  handling, evidence provenance, audit, and report schemas. A future emergency
  stop must also live in the shared core. These protections must be present even
  when the White product edition is not installed. White adds management and
  exercise-control workflows; it is not an optional safety bypass.
- Each edition will own its commands, optional dependencies, and presentation.
  An edition must not silently enable another edition's active capabilities.
- Cross-edition exchange uses versioned, secret-free evidence contracts. Purple
  can consume previously exported Red and Blue evidence without requiring both
  engines to run in the same process; integrated installations can connect them
  directly under one approved engagement.
- Black-box means limited operator knowledge, never weaker authorization.
  Discovered associations are evidence to review, not permission to probe newly
  found hosts or domains.
- Installing multiple editions should compose capabilities, not duplicate
  databases or change defaults. Passive remains the default; active activity
  still requires the same explicit scope and policy gates.

## Delivery gates

1. Catalog and published boundaries (completed).
2. Command ownership and fail-closed routing boundary (internal gateway now
   present; independently installed command routing still requires packaging
   tests).
3. Separate installable edition entry points with optional dependencies and
   tests proving one edition cannot invoke another edition's active commands,
   including one edition, arbitrary combinations, and the full suite.
4. Add the missing Blue/White/Purple capabilities and further Red/Black-box
   capabilities in small CI-verified releases. Do not advertise a standalone
   edition as available until its isolation and functional acceptance tests pass.

The next domain-capability batch remains authorization-first Active Directory
identity collection on top of the v0.31 immutable graph evidence contract.
