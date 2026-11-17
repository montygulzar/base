"""Censys hosts search — optional (CENSYS_API_ID + CENSYS_API_SECRET)."""
from __future__ import annotations
import base64
import httpx
from ..utils.validators import is_ip, is_domain
from ..utils.ratelimit import gate
from ..config import get_settings
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    s = get_settings()
    out = CollectionResult()
    v = (subject or "").strip()
    if not (s.CENSYS_API_ID and s.CENSYS_API_SECRET):
        out.findings.append(Finding("censys", "source_unavailable", {"reason": "no api credentials"}, 0.0))
        return out
    auth = base64.b64encode(f"{s.CENSYS_API_ID}:{s.CENSYS_API_SECRET}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}", "user-agent": "base-osint/0.1"}

    async with httpx.AsyncClient(headers=headers) as c:
        await gate("censys")
        if is_ip(v):
            try:
                r = await c.get(f"https://search.censys.io/api/v2/hosts/{v}", timeout=15)
                if r.status_code == 200:
                    j = (r.json() or {}).get("result", {})
                    out.entities.append(Entity("ip", v, {}, 0.9))
                    out.findings.append(Finding("censys", "host", j, 0.9))
                    for svc in j.get("services", []):
                        port = svc.get("port")
                        if port:
                            out.findings.append(Finding("censys", "service",
                                                        {"port": port, "name": svc.get("service_name"),
                                                         "transport": svc.get("transport_protocol")}, 0.85))
                else:
                    out.findings.append(Finding("censys", "http_error", {"status": r.status_code}, 0.1))
            except Exception as e:
                out.findings.append(Finding("censys", "error", {"error": str(e)}, 0.1))
            return out

        if is_domain(v):
            try:
                r = await c.post("https://search.censys.io/api/v2/hosts/search",
                                 json={"q": f"services.tls.certificates.leaf_data.subject_dn: *{v}*"},
                                 timeout=20)
                if r.status_code == 200:
                    hits = ((r.json() or {}).get("result") or {}).get("hits", [])
                    out.findings.append(Finding("censys", "domain_search",
                                                {"hits": len(hits), "hosts": [h.get("ip") for h in hits][:50]}, 0.85))
                    for h in hits[:50]:
                        ip = h.get("ip")
                        if ip and is_ip(ip):
                            out.entities.append(Entity("ip", ip, {"from": "censys"}, 0.75))
                            out.relationships.append(Relationship("domain", v, "ip", ip, "cert_seen_on",
                                                                  "censys", 0.7))
            except Exception as e:
                out.findings.append(Finding("censys", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="censys",
    name="Censys",
    subject_types=["ip", "domain"],
    description="Censys host lookup / cert-based host discovery.",
    run=run,
))
