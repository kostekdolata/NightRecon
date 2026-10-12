"""Read-only bounded identity relationship import; no credential material."""
import json
from dataclasses import dataclass
MAX_BYTES=4*1024*1024
MAX_EDGES=10000
@dataclass(frozen=True)
class IdentityEdge:
    source: str
    target: str
    relationship: str
@dataclass(frozen=True)
class IdentityEvidence:
    source: str
    edges: tuple[IdentityEdge,...]
def parse_identity_edges(data:bytes,allowed_relationships:frozenset[str]=frozenset({"MemberOf","AdminTo","HasSession","Owns"}))->IdentityEvidence:
    if len(data)>MAX_BYTES:raise ValueError("Identity export exceeds limit")
    try:obj=json.loads(data)
    except (ValueError,UnicodeError) as exc:raise ValueError("Invalid identity JSON") from exc
    edges=obj.get("edges") if isinstance(obj,dict) else None
    if not isinstance(edges,list) or len(edges)>MAX_EDGES:raise ValueError("Invalid identity edges")
    out=[]
    for e in edges:
        if not isinstance(e,dict):raise ValueError("Invalid identity edge")
        a,b,r=e.get("source"),e.get("target"),e.get("relationship")
        if not all(isinstance(x,str) and 0<len(x)<=256 for x in (a,b,r)):raise ValueError("Invalid identity fields")
        if r not in allowed_relationships:raise ValueError("Unsupported relationship")
        out.append(IdentityEdge(a,b,r))
    return IdentityEvidence("identity-edges-unverified",tuple(out))
