# v0.36.0 Unified Attack Graph

Red Night v0.36 adds a single evidence-backed graph projection for assets,
identities, groups, services, vulnerabilities, findings, and critical assets.

The projector only creates facts from explicit engagement evidence records.
Relationships with missing endpoints remain unresolved. Inferred relationships
must be explicitly labeled as inferred and stay distinguishable from observed
facts. Edge explanations retain the evidence record IDs that created them and
state that graph reachability is not an exploitability or compromise verdict.

This provides the stable graph boundary required for later attack-path analysis
without inventing relationships from labels, names, or incomplete evidence.
