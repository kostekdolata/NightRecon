# Red Night v0.47.0 Capability Completion Matrix

This branch is a substantial capability-completion milestone for authorized
security assessment. It extends existing Red Night architecture instead of
duplicating mature modules.

## Network reconnaissance

| Capability | Status | Implementation |
|---|---|---|
| Host discovery | Existing / test-ready | Bounded TCP discovery, CIDR limits, reverse DNS |
| TCP connect scanning | Extended / test-ready | Open/closed/filtered/error states, evidence, retries, summaries, budgets, pacing |
| TCP SYN scanning | New / test-ready | Explicit-scope Scapy backend, bounded ports/rate/retries, IPv4/IPv6 |
| UDP scanning | Existing / test-ready | Protocol-aware bounded probes, open/open-filtered/closed/error states |
| Service/version detection | Existing / test-ready | Banners, HTTP/TLS, active probes, software identity |
| OS fingerprinting | Existing / test-ready | Evidence-backed service/platform aggregation |
| Device role fingerprinting | New / test-ready | Evidence-backed Windows/network-device/printer/web-appliance role hints |
| Timing/rate profiles | New / test-ready | polite/normal/fast profiles; TCP connect pacing and SYN rate bounds |
| IPv6 | Existing + extended | TCP, UDP, host discovery, SYN, route and packet metadata support |
| Route/interface awareness | New / test-ready | Linux and Windows read-only local route/interface collection |
| Scriptable service probes | New / test-ready | Declarative JSON/base64/regex probes; no executable scripts |
| Scan-state evidence | Extended / test-ready | Explicit state/confidence/evidence/attempt accounting |

## Packet / traffic intelligence

| Capability | Status | Implementation |
|---|---|---|
| Live packet capture | New / test-ready | Scapy/Npcap/libpcap optional backend with packet/time ceilings |
| PCAP import/export | New / test-ready | Scapy reader/writer |
| Protocol dissection | New baseline | DNS/HTTP/TLS/SMB/SSH transport/application identification and metadata |
| Stream/session reconstruction | New / test-ready | Deterministic TCP/UDP flow grouping and ordered packet IDs |
| Filtering | New / test-ready | Host/protocol/port filters plus optional BPF capture filter |
| Conversation statistics | New / test-ready | Packet/byte/time endpoint summaries |
| Suspicious traffic detection | New baseline | DNS burst, TCP SYN fan-out, cleartext state-changing HTTP indicators |
| Evidence/artifacts | New / test-ready | DNS names, HTTP paths, TLS SNI artifact model; packet IDs |
| Finding-to-packet correlation | New / test-ready | Automatic address/port/protocol correlation into evidence links |

## Controlled validation

Existing Red Night already provides reviewed technique metadata, eligibility,
preconditions, fixed proof adapters, isolated spawned workers, authorization,
approval, action budgets, revocation, result limits, evidence contracts,
cleanup evidence, and remediation/retest lifecycle.

This branch adds:

- reviewed validation-module session lifecycle;
- created/approved/running/confirmed/not-confirmed/failed/cleanup states;
- a controlled read-only agent session over existing fixed SSH actions;
- strict action budgets and no arbitrary command text.

Red Night intentionally does **not** add a reusable arbitrary interactive shell,
payload generator, persistence framework, credential-stealing agent, or
automatic destructive exploitation. Controlled agent behavior remains fixed,
read-only, authorization-gated and evidence-oriented.

## Web and API testing

Existing Red Night already includes bounded crawling, endpoint discovery,
safe-active web assessment, forms/workflows, DAST evidence/findings, OpenAPI,
GraphQL, authenticated infrastructure/web components and retest/reporting.

This branch adds:

- loopback scoped HTTP intercept proxy;
- bounded request repeater;
- query/form/JSON parameter discovery;
- cookie Secure/HttpOnly/SameSite analysis;
- secret-minimized exchange records;
- explicit scope checks before replay/proxy forwarding.

HTTPS CONNECT traffic is not decrypted by the bounded proxy in this milestone.
TLS application assessment continues through the existing direct HTTPS,
browser, API and crawl engines rather than a generated MITM CA.

## Credentialed and identity assessment

Existing Red Night already provides:

- SSH fixed read-only inventory;
- SMB/Windows read-only assessment;
- WinRM;
- PostgreSQL/MySQL adapters;
- Active Directory and Entra identity collection;
- group/role/ownership/trust evidence;
- graph identity projection and path analysis;
- credential provider/resolution boundaries.

This branch adds secret-minimized credential-exposure detection that reports
only type/location/confidence and a one-way fingerprint, never the secret value.

## Vulnerability intelligence and attack paths

Existing Red Night already provides:

- service/software identity;
- NVD vulnerability lookup;
- CVE/CPE evidence;
- CISA KEV and EPSS enrichment;
- unified evidence graph;
- cross-domain attack-path atlas;
- validation candidates and eligibility;
- remediation/retest state.

This branch adds evidence-backed exposure prioritisation using:

- current reachability;
- CVSS severity;
- KEV presence;
- EPSS probability;
- reviewed validation state;
- documented preconditions;
- existing authorized access context;
- identity/attack-path presence.

The prioritisation layer reports an evidence-backed priority band and
exploitability-confidence label. It does not assert exploitation where evidence
is absent.

## Runtime dependencies

The new SYN and packet-capture/PCAP functions use the optional Red engine
`packet` extra:

    pip install -e "./packages/red-engine[packet]"

Live capture additionally requires the operating-system packet capture runtime
where applicable (for example Npcap on Windows or libpcap/capture capabilities
on Linux).

The native Windows installer bundles the Python Scapy backend in this branch.
The immutable Red Night Live image still uses its existing strict three-wheel
offline release contract; the Scapy backend is therefore not claimed as
embedded in that image by this milestone. Source/venv and native Windows
testing are the packet/SYN validation targets for v0.47.0.

## Verification target

Before merge/release, the branch must pass the repository's normal CI matrix:

- Ubuntu latest / Python 3.11 and 3.14
- Windows latest / Python 3.11 and 3.14
- Red Night distribution smoke tests
- existing full test suite
- new v0.47 capability tests

The branch is not considered release-ready until those checks pass.
