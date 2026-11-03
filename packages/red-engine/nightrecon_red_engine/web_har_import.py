"""Passive HAR traffic metadata importer; never stores headers, bodies, cookies, or URLs with paths."""
import json
from dataclasses import dataclass
from urllib.parse import urlsplit
MAX_BYTES=8*1024*1024
MAX_ENTRIES=10000
@dataclass(frozen=True)
class WebRequestSummary:
    origin: str
    method: str
    status: int
@dataclass(frozen=True)
class HarEvidence:
    source: str
    requests: tuple[WebRequestSummary,...]
def parse_har(data:bytes)->HarEvidence:
    if len(data)>MAX_BYTES:raise ValueError("HAR exceeds size limit")
    try: obj=json.loads(data)
    except (ValueError,UnicodeError) as exc:raise ValueError("Invalid HAR JSON") from exc
    entries=obj.get("log",{}).get("entries") if isinstance(obj,dict) else None
    if not isinstance(entries,list) or len(entries)>MAX_ENTRIES:raise ValueError("Invalid HAR entries")
    out=[]
    for item in entries:
        if not isinstance(item,dict):raise ValueError("Invalid HAR entry")
        req=item.get("request",{});resp=item.get("response",{})
        url=req.get("url","");method=req.get("method","")
        parsed=urlsplit(url)
        if parsed.scheme not in ("http","https") or not parsed.hostname or not isinstance(method,str):raise ValueError("Invalid HAR request")
        status=resp.get("status",0)
        if type(status) is not int or not 0<=status<=999:raise ValueError("Invalid HAR status")
        out.append(WebRequestSummary(parsed.scheme+"://"+parsed.hostname+((":"+str(parsed.port)) if parsed.port else ""),method[:16],status))
    return HarEvidence("har-metadata-unverified",tuple(out))
