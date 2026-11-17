"""Robtex free API lookups — IP or domain, keyless."""
from __future__ import annotations
import httpx
from ..utils.validators import is_ip, is_domain, normalise_domain, is_private_ip
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        if is_ip(v):
            if is_private_ip(v):
                out.findings.append(Finding("robtex", "private_address", {"ip": v}, 1.0))
                return out
            out.entities.append(Entity("ip", v, {}, 0.95))
            try:
                r = await c.get(f"https://freeapi.robtex.com/ipquery/{v}", timeout=15)
                if r.status_code == 200:
                    j = r.json()
                    out.findings.append(Finding("robtex", "ipquery", j, 0.85))
                    for row in (j.get("pas") or [])[:200]:
                        host = (row or {}).get("o")
                        if host and is_domain(host):
                            out.entities.append(Entity("domain", host.lower(), {"from": "robtex"}, 0.75))
                            out.relationships.append(Relationship("domain", host.lower(), "ip", v,
                                                                  "resolves_to", "robtex", 0.8))
            except Exception as e:
                out.findings.append(Finding("robtex", "error", {"error": str(e)}, 0.1))
            return out
        d = normalise_domain(v)
        if is_domain(d):
            out.entities.append(Entity("domain", d, {}, 0.95))
            try:
                r = await c.get(f"https://freeapi.robtex.com/pdns/forward/{d}", timeout=15)
                if r.status_code == 200:
                    # response is JSONL (lines of JSON objects)
                    rows = [__import__("json").loads(ln) for ln in r.text.splitlines() if ln.strip()]
                    out.findings.append(Finding("robtex", "pdns_forward",
                                                {"count": len(rows),
                                                 "rows": rows[:100]}, 0.85))
                    for row in rows[:100]:
                        rrdata = (row or {}).get("rrdata") or ""
                        if is_ip(rrdata):
                            out.entities.append(Entity("ip", rrdata, {"from": "robtex"}, 0.75))
                            out.relationships.append(Relationship("domain", d, "ip", rrdata,
                                                                  "resolves_to", "robtex", 0.8))
            except Exception as e:
                out.findings.append(Finding("robtex", "error", {"error": str(e)}, 0.1))
            return out
    out.findings.append(Finding("robtex", "invalid_input", {"input": subject}, 0.1))
    return out


register(Module(
    key="robtex",
    name="Robtex",
    subject_types=["ip", "domain"],
    description="Robtex free passive-DNS forward/reverse (keyless).",
    run=run,
))
