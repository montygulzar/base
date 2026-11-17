"""EPSS — Exploit Prediction Scoring System. FIRST.org, keyless.

Returns the daily-updated likelihood that a CVE will be exploited in
the next 30 days, plus its percentile.
"""
from __future__ import annotations
import httpx
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip().upper()
    if not v.startswith("CVE-"):
        out.findings.append(Finding("epss", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("cve", v, {}, 0.95))
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            r = await c.get("https://api.first.org/data/v1/epss", params={"cve": v}, timeout=15)
            if r.status_code == 200:
                data = (r.json() or {}).get("data") or []
                out.findings.append(Finding("epss", "score",
                                            {"cve": v, "data": data}, 0.95 if data else 0.5))
            else:
                out.findings.append(Finding("epss", "http_error",
                                            {"status": r.status_code}, 0.1))
        except Exception as e:
            out.findings.append(Finding("epss", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="epss",
    name="EPSS score",
    subject_types=["document", "domain", "company"],
    description="FIRST.org EPSS exploit-probability score for a CVE.",
    run=run,
))
