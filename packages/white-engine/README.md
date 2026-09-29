# White Night engine distribution

`nightrecon-white-engine` is the independently packaged White Night control-plane
engine.

The `0.1.0a3` development package adds deterministic local compilation of immutable White Night engagement/ROE intent into the shared-core execution-policy contract. Compilation remains network-free and does not publish, approve, persist, or execute the resulting policy. Scope exclusions are projected exactly where representable and compilation fails closed rather than widening intent.

The engine depends only on the mandatory `nightrecon-shared-core==0.41.0`
package. It does not depend on Red, Blue, Purple, Black, or the legacy
`nightrecon` distribution.

Future White batches will add engagement, ROE, approval, evidence-custody,
audit, exercise-control, and reporting behavior behind this package boundary.
The same engine package is intended for standalone, composed full-stack, and
White Night Live USB deployments.
