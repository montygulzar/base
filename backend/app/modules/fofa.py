"""FOFA search module — optional (FOFA_API_EMAIL + FOFA_API_KEY)."""
from __future__ import annotations
import base64
import httpx
from ..utils.ratelimit import gate
from ..utils.validators import is_ip, is_domain
from ..config import get_settings
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    s = get_settings()
    out = CollectionResult()
    v = (subject or "").strip()
    if not (s.FOFA_API_EMAIL and s.FOFA_API_KEY):
        out.findings.append(Finding("fofa", "source_unavailable", {"reason": "no api credentials"}, 0.0))
        return out
    if is_ip(v):
        q = f'ip="{v}"'
    elif is_domain(v):
        q = f'domain="{v}"'
    else:
        q = f'"{v}"'
    qb = base64.b64encode(q.encode()).decode()

    await gate("fofa")
    async with httpx.AsyncClient() as c:
        try:
            r = await c.get("https://fofa.info/api/v1/search/all",
                            params={"email": s.FOFA_API_EMAIL, "key": s.FOFA_API_KEY,
                                    "qbase64": qb, "size": 100,
                                    "fields": "ip,port,host,title,domain,country"},
                            timeout=25)
            if r.status_code == 200:
                j = r.json()
                results = j.get("results") or []
                out.findings.append(Finding("fofa", "search",
                                            {"query": q, "size": j.get("size"), "page": j.get("page"),
                                             "results": results[:100]}, 0.85))
                for row in results[:100]:
                    if len(row) >= 5:
                        ip, port, host, title, domain = row[0], row[1], row[2], row[3], row[4]
                        if ip and is_ip(ip):
                            out.entities.append(Entity("ip", ip, {"port": port, "from": "fofa"}, 0.75))
                        if domain and is_domain(domain):
                            out.entities.append(Entity("domain", domain.lower(), {"from": "fofa"}, 0.75))
            else:
                out.findings.append(Finding("fofa", "http_error", {"status": r.status_code,
                                                                   "body": r.text[:200]}, 0.1))
        except Exception as e:
            out.findings.append(Finding("fofa", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="fofa",
    name="FOFA",
    subject_types=["ip", "domain"],
    description="FOFA search (requires account email + key).",
    run=run,
))
