"""ZoomEye search — optional (ZOOMEYE_API_KEY)."""
from __future__ import annotations
import httpx
from ..utils.ratelimit import gate
from ..utils.validators import is_ip, is_domain
from ..config import get_settings
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    s = get_settings()
    out = CollectionResult()
    v = (subject or "").strip()
    if not s.ZOOMEYE_API_KEY:
        out.findings.append(Finding("zoomeye", "source_unavailable", {"reason": "no api key"}, 0.0))
        return out
    endpoint = "host" if is_ip(v) else "web"
    await gate("zoomeye")
    async with httpx.AsyncClient() as c:
        try:
            r = await c.get(f"https://api.zoomeye.hk/{endpoint}/search",
                            params={"query": v, "page": 1, "pagesize": 20},
                            headers={"API-KEY": s.ZOOMEYE_API_KEY}, timeout=25)
            if r.status_code == 200:
                j = r.json()
                matches = j.get("matches") or []
                out.findings.append(Finding("zoomeye", endpoint,
                                            {"total": j.get("total"), "matches_sample": matches[:20]}, 0.85))
                for m in matches[:20]:
                    ip = m.get("ip") or ((m.get("site") or "") if endpoint == "web" else None)
                    if ip and is_ip(ip):
                        out.entities.append(Entity("ip", ip, {"from": "zoomeye"}, 0.75))
                        if is_domain(v):
                            out.relationships.append(Relationship("domain", v, "ip", ip,
                                                                  "seen_hosting", "zoomeye", 0.7))
                    site = m.get("site")
                    if site and is_domain(site):
                        out.entities.append(Entity("domain", site.lower(), {"from": "zoomeye"}, 0.75))
            else:
                out.findings.append(Finding("zoomeye", "http_error",
                                            {"status": r.status_code, "body": r.text[:200]}, 0.1))
        except Exception as e:
            out.findings.append(Finding("zoomeye", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="zoomeye",
    name="ZoomEye",
    subject_types=["ip", "domain"],
    description="ZoomEye host/web search.",
    run=run,
))
