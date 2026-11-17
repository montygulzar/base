"""CISA Known Exploited Vulnerabilities catalogue — keyless public JSON.

Scans the investigation's existing CVE entities (and the subject value
if it's a CVE) against CISA's KEV catalogue. Hits are the vulns
actually being exploited in the wild.
"""
from __future__ import annotations
import httpx
from sqlalchemy import select
from ..db import SessionLocal
from ..models import Entity
from .base import Module, Finding, Entity as E, CollectionResult, RunContext, register

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_cache: list[dict] | None = None


async def _load(c: httpx.AsyncClient) -> list[dict]:
    global _cache
    if _cache is not None:
        return _cache
    try:
        r = await c.get(KEV_URL, timeout=30)
        if r.status_code == 200:
            _cache = (r.json() or {}).get("vulnerabilities") or []
            return _cache
    except Exception:
        pass
    _cache = []
    return _cache


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        catalogue = await _load(c)
    if not catalogue:
        out.findings.append(Finding("kev", "source_unavailable",
                                    {"reason": "could not load KEV catalogue"}, 0.0))
        return out
    cve_index = {v.get("cveID"): v for v in catalogue if v.get("cveID")}
    cves_to_check: list[str] = []
    v = (subject or "").strip().upper()
    if v.startswith("CVE-"):
        cves_to_check.append(v)
        out.entities.append(E("cve", v, {}, 0.95))
    else:
        async with SessionLocal() as db:
            ents = (await db.execute(
                select(Entity).where(Entity.investigation_id == ctx.investigation_id,
                                     Entity.type == "cve"))).scalars().all()
            cves_to_check = [e.value for e in ents]
    hits = [cve_index[c] for c in cves_to_check if c in cve_index]
    out.findings.append(Finding("cisa_kev", "scan",
                                {"catalogue_size": len(catalogue),
                                 "checked": len(cves_to_check),
                                 "hit_count": len(hits),
                                 "hits": hits}, 0.95 if hits else 0.6))
    for h in hits:
        out.entities.append(E("cve", h["cveID"], {
            "kev": True,
            "vendor": h.get("vendorProject"), "product": h.get("product"),
            "due_date": h.get("dueDate"),
            "known_ransomware_use": h.get("knownRansomwareCampaignUse"),
        }, 0.95))
    return out


register(Module(
    key="kev",
    name="CISA KEV",
    subject_types=["document", "domain", "company"],
    description="Flags CVE entities present in CISA's Known Exploited Vulnerabilities catalogue.",
    run=run,
))
