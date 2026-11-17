"""Company / organisation intelligence.

Uses SEC EDGAR (no key) for US filers and OpenCorporates (optional key)
for broader jurisdictions. Also collects public media hits via domain
association if the subject value looks like a domain name.
"""
from __future__ import annotations
import httpx
from urllib.parse import quote_plus
from ..config import get_settings
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    s = get_settings()
    out = CollectionResult()
    name = (subject or "").strip()
    if not name:
        out.findings.append(Finding("company", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("org", name, {}, 0.9))

    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1 research@local"}) as client:
        try:
            r = await client.get(
                f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&company={quote_plus(name)}&type=10-K&dateb=&owner=include&count=20&output=atom",
                timeout=20,
            )
            if r.status_code == 200 and "<entry" in r.text:
                out.findings.append(Finding("sec_edgar", "filings_feed",
                                            {"atom_bytes": len(r.text), "hits": r.text.count("<entry")}, 0.8))
        except Exception as e:
            out.findings.append(Finding("sec_edgar", "error", {"error": str(e)}, 0.1))

        if s.OPENCORPORATES_API_KEY:
            try:
                r = await client.get(
                    f"https://api.opencorporates.com/v0.4/companies/search?q={quote_plus(name)}&api_token={s.OPENCORPORATES_API_KEY}",
                    timeout=20,
                )
                if r.status_code == 200:
                    j = r.json()
                    hits = (j.get("results") or {}).get("companies") or []
                    out.findings.append(Finding("opencorporates", "search", {"hits": len(hits), "companies": hits[:50]}, 0.85))
                    for h in hits[:50]:
                        c = h.get("company") or {}
                        v = c.get("name") or ""
                        if v:
                            out.entities.append(Entity("org", v, {"jurisdiction": c.get("jurisdiction_code"),
                                                                  "number": c.get("company_number")}, 0.75))
                            out.relationships.append(Relationship("org", name, "org", v, "candidate_match",
                                                                  "opencorporates", 0.6))
            except Exception as e:
                out.findings.append(Finding("opencorporates", "error", {"error": str(e)}, 0.1))
        else:
            out.findings.append(Finding("opencorporates", "source_unavailable", {"reason": "no api key"}, 0.0))

    return out


register(Module(
    key="company",
    name="Company intelligence",
    subject_types=["company"],
    description="SEC EDGAR + OpenCorporates (optional). Candidate matches only.",
    run=run,
))
