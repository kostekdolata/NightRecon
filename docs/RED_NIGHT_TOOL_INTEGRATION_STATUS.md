# Red Night integration verification

Development branch: `red-night-v047-nmap-evidence-import`.

The third-party adapters are **read-only** and **not integrated with Red Night's
authoritative assessment storage or UI**. Imported content remains unverified.

## Run focused tests

```bash
python -m pip install -e ./packages/shared-core -e ./packages/red-engine
python -m unittest discover -s tests -p 'test_nmap_import.py' -v
python -m unittest discover -s tests -p 'test_pcap_import.py' -v
python -m unittest discover -s tests -p 'test_metasploit_catalogue.py' -v
python -m unittest discover -s tests -p 'test_evidence_correlation.py' -v
```

## Security and trust boundaries

- Imports never authorise network actions or invoke external binaries.
- Imported software and vulnerability metadata are *not* proof of exploitation.
- An empty engagement allowlist must produce no correlated hosts.
- Scope always comes from Red Night's existing engagement authorisation.
- Review test results and branch protection checks before merging.

## Current implementation limits

- Nmap: XML observation parsing only; no scan execution or automatic inventory mutation.
- PCAP: classic PCAP conversation metadata only; no PCAPNG, dissectors, or capture.
- Metasploit: custom interchange JSON metadata only; no RPC or module execution.
- Correlation: in-memory summary only; not the canonical evidence pipeline.
