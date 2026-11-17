"""Tranco popularity rank — keyless. Tells you if a domain is a top-N
property. Useful for triaging look-alikes (legit top-1k sites need
different handling from random .xyz domains).
"""
from __future__ import annotations
import httpx
from ..utils.validators import normalise_domain, is_domain
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    d = normalise_domain(subject)
    if not is_domain(d):
        out.findings.append(Finding("tranco", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("domain", d, {}, 0.9))
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            r = await c.get(f"https://tranco-list.eu/api/ranks/domain/{d}", timeout=15)
            if r.status_code == 200:
                j = r.json()
                rnk = j.get("ranks") or []
                latest = rnk[0] if rnk else None
                out.findings.append(Finding("tranco", "rank",
                                            {"domain": d, "latest": latest,
                                             "history": rnk[:50]},
                                            0.95 if latest else 0.3))
            elif r.status_code == 404:
                out.findings.append(Finding("tranco", "not_ranked", {"domain": d}, 0.9))
            else:
                out.findings.append(Finding("tranco", "http_error",
                                            {"status": r.status_code}, 0.1))
        except Exception as e:
            out.findings.append(Finding("tranco", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="tranco",
    name="Tranco rank",
    subject_types=["domain"],
    description="Popularity rank from the Tranco research list (keyless).",
    run=run,
))
