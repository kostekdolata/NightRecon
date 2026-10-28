"""Safe export of imported identity edges to Graphviz DOT.

Labels are escaped and bounded. This is a visualisation format, not
an authorisation or attack-path verification engine.
"""
from __future__ import annotations
import json
from .identity_interop import IdentityEvidence

MAX_NODES = 10000
MAX_DOT_BYTES = 2 * 1024 * 1024

def identity_to_dot(evidence: IdentityEvidence) -> str:
    nodes = {v for edge in evidence.edges for v in (edge.source,edge.target)}
    if len(nodes) > MAX_NODES:
        raise ValueError("Too many identity graph nodes")
    result = ['digraph RedNightIdentity {', '  graph [rankdir="LR"];']
    for node in sorted(nodes):
        result.append("  " + json.dumps(node, ensure_ascii=True) + ";")
    for edge in sorted(evidence.edges, key=lambda e:(e.source,e.target,e.relationship)):
        result.append("  "+json.dumps(edge.source)+" -> "+json.dumps(edge.target)+
                      " [label="+json.dumps(edge.relationship)+"];")
    result.append("}")
    output="\n".join(result)+"\n"
    if len(output.encode("utf-8")) > MAX_DOT_BYTES:
        raise ValueError("Identity graph export exceeds size limit")
    return output
