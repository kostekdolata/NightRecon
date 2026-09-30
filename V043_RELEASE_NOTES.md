# Red Night v0.43.0 Release Notes

Red Night v0.43.0 is the Controlled Validation Intelligence release.

It builds on v0.42 Cross-Domain Exposure Intelligence by turning proposal-only
validation candidates into explicitly selected, authorization-bound, isolated
read-only validation actions with durable evidence, cleanup/retest linkage, and
reviewed ATT&CK/comparison metadata.

## Highlights

- reviewed metadata-only controlled-validation technique registry
- exact candidate-to-technique eligibility with no automatic selection
- immutable adapter precondition/postcondition contracts
- isolated revocable workers for bounded TCP, TLS-fingerprint, and HTTP HEAD proofs
- one-action authorization reservation with continuous revocation/scope/window checks
- deterministic durable validation + cleanup evidence and idempotent persistence
- deterministic remediation/retest linkage from exact persisted evidence
- reviewed ATT&CK relationship metadata with explicit non-equivalence semantics
- deterministic fixture comparison with reproducible fingerprints and non-parity interpretation

## Packaging

The coordinated stable distributions are:

- `nightrecon-red-night==0.43.0`
- `nightrecon-red-engine==0.43.0`
- `nightrecon-shared-core==0.43.0`

Legacy `nightrecon==0.31.0` remains the compatibility bridge and pins matching
Red 0.43 dependencies.

## Safety boundary

Current live validation remains deliberately small and read-only. v0.43 does
not expose arbitrary command execution, shell/PowerShell/SQL, credential
harvesting, exploit payloads, arbitrary HTTP bodies/paths, cloud/directory
writes, persistence, privilege changes, autonomous lateral movement,
high-impact validation, or autonomous technique selection.

## Broader acceptance remains open

Stable v0.43 does not claim parity with ATT&CK, Caldera, Metasploit, Cobalt
Strike, Nmap, Burp/ZAP, BloodHound, or another specialist product. Live
authorized specialist comparisons, broader discovery/relationship coverage, and
professional multi-operator reporting remain measured work under
`RED_ACCEPTANCE.md`.
