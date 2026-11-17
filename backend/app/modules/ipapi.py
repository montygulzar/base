"""ipapi.co — keyless free IP geolocation. Rate-limited but very usable
for 1-off lookups.
"""
from __future__ import annotations
import httpx
from ..utils.validators import is_ip, is_private_ip
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    if not is_ip(v):
        out.findings.append(Finding("ipapi", "invalid_input", {"input": subject}, 0.1))
        return out
    if is_private_ip(v):
        out.findings.append(Finding("ipapi", "private_address", {"ip": v}, 1.0))
        return out
    out.entities.append(Entity("ip", v, {}, 0.95))
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            r = await c.get(f"https://ipapi.co/{v}/json/", timeout=15)
            if r.status_code == 200:
                out.findings.append(Finding("ipapi", "geo", r.json(), 0.85))
            elif r.status_code == 429:
                out.findings.append(Finding("ipapi", "rate_limited", {}, 0.3))
            else:
                out.findings.append(Finding("ipapi", "http_error",
                                            {"status": r.status_code}, 0.1))
        except Exception as e:
            out.findings.append(Finding("ipapi", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="ipapi",
    name="ipapi.co geo",
    subject_types=["ip"],
    description="Keyless IP geolocation (ipapi.co).",
    run=run,
))
