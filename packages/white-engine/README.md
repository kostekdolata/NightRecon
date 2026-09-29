# White Night engine distribution

`nightrecon-white-engine` is the independently packaged White Night control-plane
engine.

The `0.2.0a1` package adds White Night's immutable engagement, scope, rules-of-engagement, action-constraint, contact/window, and data-handling authoring domain. The command surface remains informational only. It does not scan targets, compile execution authorization, grant approvals, or execute another Night's capabilities.

The engine depends only on the mandatory `nightrecon-shared-core==0.41.0`
package. It does not depend on Red, Blue, Purple, Black, or the legacy
`nightrecon` distribution.

Future White batches will add engagement, ROE, approval, evidence-custody,
audit, exercise-control, and reporting behavior behind this package boundary.
The same engine package is intended for standalone, composed full-stack, and
White Night Live USB deployments.
