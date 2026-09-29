# White Night engine distribution

`nightrecon-white-engine` is the independently packaged White Night control-plane
engine.

The `0.1.0a2` development package adds the immutable White Night engagement, scope, and ROE authoring domain above the previously verified package boundary. It remains non-active: the models describe engagement intent and generate deterministic human-readable ROE output, but they do not authorize actions, grant approvals, compile executable policy, scan targets, or execute another Night's capabilities.

The engine depends only on the mandatory `nightrecon-shared-core==0.41.0`
package. It does not depend on Red, Blue, Purple, Black, or the legacy
`nightrecon` distribution.

Future White batches will add engagement, ROE, approval, evidence-custody,
audit, exercise-control, and reporting behavior behind this package boundary.
The same engine package is intended for standalone, composed full-stack, and
White Night Live USB deployments.
