"""CrowdSec community CTI — free, no key. IP reputation and seen-by-sensors
count.
"""
from __future__ import annotations
import httpx
from ..utils.validators import is_ip, is_private_ip
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    if not is_ip(v):
        out.findings.append(Finding("crowdsec", "invalid_input", {"input": subject}, 0.1))
        return out
    if is_private_ip(v):
        out.findings.append(Finding("crowdsec", "private_address", {"ip": v}, 1.0))
        return out
    out.entities.append(Entity("ip", v, {}, 0.9))
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            r = await c.get(f"https://cti.api.crowdsec.net/v2/smoke/{v}", timeout=15)
            if r.status_code == 200:
                out.findings.append(Finding("crowdsec", "smoke", r.json(), 0.9))
            elif r.status_code == 404:
                out.findings.append(Finding("crowdsec", "not_seen", {"ip": v}, 0.9))
            else:
                out.findings.append(Finding("crowdsec", "http_error",
                                            {"status": r.status_code}, 0.1))
        except Exception as e:
            out.findings.append(Finding("crowdsec", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="crowdsec",
    name="CrowdSec CTI",
    subject_types=["ip"],
    description="CrowdSec community smoke endpoint (keyless).",
    run=run,
))
