# Red Night — 20-tool integration standard and audit

Status: **initial evidence-bounded audit**, not a claim that tools are installed or operational. Baseline: master `20b8c79677a3cb00e89cb15d9b8ab1484dc20c56`. Tool selection is locked as an initial 20-slot product target; every adapter requires separate acceptance.

## Classification

- **Existing guarded surface**: named entry points found in `packages/red-engine/nightrecon_red_engine/advanced_cli.py`; requires end-to-end implementation, installed-tool, policy and output tests before calling it operational.
- **Native overlap**: Red has some related functionality, but this is not evidence of an external product integration.
- **Unverified / gap**: no matching entry point found in the inspected CLI and acceptance standard; repository-wide discovery and tests are still required before declaring absence.

| # | Tier | Tool | Initial status | Integration contract |
|---|---|---|---|---|
| 1 | 1 | Nmap | Existing guarded surface (`nmap-governed`) | Trusted binary, exact-scope target, bounded TCP connect, audited output |
| 2 | 1 | Amass | Unverified / gap | Bounded authorized domain enumeration, provenance and passive/active distinction |
| 3 | 1 | ProjectDiscovery httpx | Unverified / gap | Approved host/URL inputs, rate limits, JSONL evidence |
| 4 | 1 | Nuclei | Existing guarded surface (planned execution/consumer) | Reviewed pinned templates, explicit safety classification, structured evidence |
| 5 | 1 | Greenbone/OpenVAS | Unverified / gap | Dedicated service with scoped targets, credential isolation, polling and findings import |
| 6 | 1 | OWASP ZAP | Existing guarded surface (consumer) | API/service integration, explicit passive vs active approval, structured alerts |
| 7 | 1 | Wireshark/TShark | Existing guarded surface (`tshark-inspect`) | Verified binary and bounded local PCAP; capture requires separate authority |
| 8 | 2 | Metasploit Framework | Existing guarded surface (consumer) | Isolated worker, explicit technique approval, bounded execution and cleanup |
| 9 | 2 | BloodHound CE | Native identity/graph overlap; external integration unverified | Scoped AD/Entra data import/export, provenance and path mapping |
| 10 | 2 | Impacket | Unverified / gap | Read-only protocol assessment first; intrusive auth actions separately approved |
| 11 | 2 | Prowler | Unverified / gap | Read-only least-privilege cloud credentials, tenant/account scope, JSON/CSV findings |
| 12 | 2 | Trivy | Unverified / gap | Offline/local image, dependency and IaC inspection with pinned databases |
| 13 | 2 | Semgrep | Unverified / gap | Local source inspection, trusted rules and SARIF/JSON results |
| 14 | 2 | MobSF | Unverified / gap | Isolated mobile artifact submission, static analysis API, retention controls |
| 15 | 3 | Ghidra | Unverified / gap | Isolated headless static analysis, bounded samples, exported findings |
| 16 | 3 | Volatility 3 | Unverified / gap | Offline memory image analysis with forensic provenance and resource limits |
| 17 | 3 | MITRE CALDERA | Native ATT&CK planning overlap; operational integration unverified | Isolated approved lab emulation only, explicit operations/agents and kill switch |
| 18 | 3 | Kismet | Unverified / gap | Dedicated permitted radio/capture interface, passive default and geographic/legal controls |
| 19 | 3 | Binwalk | Unverified / gap | Isolated offline firmware inspection, extraction safety and artifact limits |
| 20 | 3 | garak | Unverified / gap | Approved test endpoint/model, bounded probes, redaction and structured results |

## Common automation contract

1. **Discover** adapter capability, version, license, platform support and prerequisites. Missing binaries/services/credentials must produce `unavailable`, never a false pass.
2. **Plan** from an engagement's exact allowlisted assets and operator-selected objective. Tool selection must be deterministic or explainable, and cannot widen scope.
3. **Classify** each action as offline/read-only, network-active, credentialed, intrusive or disruptive. Intrusive/disruptive actions need distinct human approval; cloud/identity credentials must be least privilege.
4. **Execute** only through registered, trusted, bounded commands or authenticated service adapters, with isolated workers where needed. Enforce timeouts, concurrency, rate limits, cancellation and emergency stop.
5. **Ingest** versioned machine-readable output with source tool/version, input scope, timestamps, artifact digests and run identifiers. Treat third-party output as untrusted data, never executable instructions.
6. **Correlate** evidence without silently promoting a tool alert to confirmed exploitability. Preserve conflicting observations and missing evidence.
7. **Report and retest** with explicit finding status, severity evidence, remediation and reproducible comparison identifiers.

## Delivery order and acceptance

- **Tier 1**: fully verify existing Nmap/Nuclei/ZAP/TShark paths; add Amass, httpx and Greenbone in small, separately tested batches. Prove an end-to-end *synthetic/offline* cross-tool finding workflow.
- **Tier 2**: verify Metasploit and BloodHound boundaries; add Impacket, Prowler, Trivy, Semgrep and MobSF. Start with static/read-only paths, not exploit execution.
- **Tier 3**: add offline Ghidra/Volatility/Binwalk, then isolated garak/Kismet, and finally strictly controlled CALDERA lab orchestration.
- Every batch must include unit/contract tests, missing-tool fail-closed behavior, scope and approval negative tests, malformed-output tests, cross-platform or platform-gated CI, and existing-regression verification.
- Real-life tests, specialist parity claims and hardware validation remain **deferred until product feature completion**. Automated safety tests remain mandatory now.

## Next engineering action

Audit the full module tree and tests for each tool, then implement the first missing **read-only** adapter (suggested: Semgrep or Trivy) behind the existing command registry and evidence contracts. Do not wire automatic execution until that adapter's policy, output and cancellation tests pass.
