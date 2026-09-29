# White Night engine distribution

`nightrecon-white-engine` is the independently packaged White Night control-plane
engine.

The `0.1.0a5` development package adds evidence custody and tamper-evident audit on top of the engagement, policy, and approval foundations. It governs the existing shared-core EvidenceRecord contract with classification/retention policy, derivation lineage, chain-of-custody events, integrity manifests, portable export verification, append-only logical audit history, and atomic local stores. Evidence and audit operations remain local and network-free and never grant authorization.

The engine depends only on the mandatory `nightrecon-shared-core==0.41.0`
package. It does not depend on Red, Blue, Purple, Black, or the legacy
`nightrecon` distribution.

Future White batches will add engagement, ROE, approval, evidence-custody,
audit, exercise-control, and reporting behavior behind this package boundary.
The same engine package is intended for standalone, composed full-stack, and
White Night Live USB deployments.
