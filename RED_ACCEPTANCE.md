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
| [BloodHound](https://bloodhound.specterops.io/get-started/introduction) | AD/Entra identity relationships and useful paths to critical assets | Offline identity graph, provenance, bounded paths; no AD/Entra collectors | Authorized collectors, privilege/trust modeling, path explanations, incomplete-evidence handling, and lab validation |
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

## Current batch

`packages/red-night/` builds a separate development-preview Red Night
distribution that depends on the existing NightRecon shared runtime. A distinct
`red-night-app` command delegates to the already verified Red gateway. Wheel
install/uninstall smoke tests cover isolated Red-app and combined legacy/Red-app
installations on Linux and Windows with Python 3.11 and 3.14. Complete engine
isolation, optional dependency division, and composition with the four future
Night applications remain open; the product is not finished or released.

An offline directory-export bridge, now exposed via `red-night identity import`,
accepts only bounded normalized
JSON with explicitly labeled users, groups, and group-member DNs. It maps
present entries to deterministic graph identities and observed membership
evidence; out-of-snapshot references are counted as unresolved and create no
graph edge. Unexpected fields, including credentials, and malformed or
over-budget exports are rejected. The CLI returns a label-free summary by
default and exposes full graph labels only on `--include-graph`. This is not a
live AD/Entra collector; it needs authorized real-world integration and lab
benchmarking before the identity gate can close.

The `red-night` entry point routes existing assessment commands through the
fail-closed Red gateway. Packaged-command smoke tests verify the installed
launcher, the scope-aware scan help, catalog, and denied unknown commands on
the Python/OS CI matrix. This is a shared NightRecon distribution, so the
independent installation gate remains open.

The earlier Red path-review primitive orders a bounded query's existing paths
for **analyst inspection** using only the count of inferred relationships, hop
count, and stable identifiers. It validates every node and edge against the
source graph, retains truncation and provenance through the original path, and
states explicitly that the order is neither risk nor exploitability. It does
not execute an attack, assign an ATT&CK technique, or add a network collector.

The next substantial product step is splitting the mandatory shared safety core
from Red-owned engine dependencies while preserving the legacy CLI, followed
by authorization-first live identity collectors and lab-backed assessment.
