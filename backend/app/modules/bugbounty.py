"""Bug-bounty program scope lookup.

Uses the ProjectDiscovery `chaos-bugbounty-list` (public JSON) to resolve
a subject domain to any bug-bounty programs that list it in scope.
HackerOne and Bugcrowd public programs are covered.
"""
from __future__ import annotations
import httpx
from ..utils.validators import normalise_domain, is_domain
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register

CHAOS = "https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/main/chaos-bugbounty-list.json"


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    d = normalise_domain(subject)
    if not is_domain(d):
        out.findings.append(Finding("bugbounty", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("domain", d, {}, 0.9))
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            r = await c.get(CHAOS, timeout=20)
            if r.status_code != 200:
                out.findings.append(Finding("chaos_bb", "http_error", {"status": r.status_code}, 0.1))
                return out
            data = r.json()
            progs = data.get("programs") or []
            matches = []
            for p in progs:
                for dom in p.get("domains") or []:
                    low = dom.lower()
                    if low == d or low.endswith("." + d):
                        matches.append({"program": p.get("name"), "url": p.get("url"),
                                        "bounty": p.get("bounty"), "swag": p.get("swag"),
                                        "logo": p.get("logo"), "matched": low})
                        break
            out.findings.append(Finding("chaos_bb", "programs",
                                        {"count": len(matches), "programs": matches}, 0.9 if matches else 0.4))
            for m in matches:
                nm = m["program"] or "program"
                out.entities.append(Entity("org", nm, {"bb_program_url": m["url"]}, 0.85))
                out.relationships.append(Relationship("domain", d, "org", nm,
                                                      "in_bb_scope", "chaos_bb", 0.9,
                                                      {"program_url": m["url"]}))
        except Exception as e:
            out.findings.append(Finding("chaos_bb", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="bugbounty",
    name="Bug-bounty scope",
    subject_types=["domain"],
    description="Checks ProjectDiscovery's chaos public bug-bounty scope list.",
    run=run,
))
