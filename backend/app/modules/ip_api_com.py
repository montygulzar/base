"""ip-api.com — second keyless geolocation source."""
from __future__ import annotations
import httpx
from ..utils.validators import is_ip, is_private_ip
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    if not is_ip(v):
        out.findings.append(Finding("ip_api_com", "invalid_input", {"input": subject}, 0.1))
        return out
    if is_private_ip(v):
        out.findings.append(Finding("ip_api_com", "private_address", {"ip": v}, 1.0))
        return out
    out.entities.append(Entity("ip", v, {}, 0.95))
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            r = await c.get(f"http://ip-api.com/json/{v}",
                            params={"fields": "66846719"}, timeout=12)
            if r.status_code == 200:
                out.findings.append(Finding("ip_api_com", "geo", r.json(), 0.85))
            else:
                out.findings.append(Finding("ip_api_com", "http_error",
                                            {"status": r.status_code}, 0.1))
        except Exception as e:
            out.findings.append(Finding("ip_api_com", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="ip_api_com",
    name="ip-api.com geo",
    subject_types=["ip"],
    description="Second keyless geo source (ip-api.com, 45 req/min).",
    run=run,
))
