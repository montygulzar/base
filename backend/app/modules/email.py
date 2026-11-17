"""Email intelligence — syntax/domain/MX/SPF/DMARC, HIBP breach exposure."""
from __future__ import annotations
import asyncio
import hashlib
import httpx
import dns.asyncresolver
from ..utils.validators import is_email
from ..config import get_settings
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register

RESOLVER = dns.asyncresolver.Resolver()
RESOLVER.lifetime = 8.0


async def _dns(name: str, rtype: str) -> list[str]:
    try:
        a = await RESOLVER.resolve(name, rtype)
        return [r.to_text().strip('"') for r in a]
    except Exception:
        return []


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    s = get_settings()
    out = CollectionResult()
    email = (subject or "").strip().lower()
    if not is_email(email):
        out.findings.append(Finding("email", "invalid_input", {"input": subject}, 0.1))
        return out
    local, domain = email.split("@", 1)
    out.entities.append(Entity("email", email, {"domain": domain}, 0.95))
    out.entities.append(Entity("domain", domain, {"from": "email"}, 0.9))
    out.relationships.append(Relationship("email", email, "domain", domain, "mailbox_at", "self", 0.98))

    mx, spf_txt, dmarc = await asyncio.gather(
        _dns(domain, "MX"), _dns(domain, "TXT"), _dns(f"_dmarc.{domain}", "TXT"),
    )
    spf = [t for t in spf_txt if t.lower().startswith("v=spf1")]
    out.findings.append(Finding("dns", "mx", {"records": mx}, 0.95 if mx else 0.2))
    out.findings.append(Finding("dns", "spf", {"records": spf}, 0.9 if spf else 0.2))
    out.findings.append(Finding("dns", "dmarc", {"records": dmarc}, 0.9 if dmarc else 0.2))

    out.findings.append(Finding("hash", "sha256", {"sha256": hashlib.sha256(email.encode()).hexdigest()}, 1.0))

    if s.HIBP_API_KEY:
        try:
            async with httpx.AsyncClient() as c:
                r = await c.get(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false",
                    headers={"hibp-api-key": s.HIBP_API_KEY, "user-agent": "base-osint"},
                    timeout=15,
                )
                if r.status_code == 200:
                    breaches = r.json()
                    out.findings.append(Finding("hibp", "breaches",
                                                {"count": len(breaches), "breaches": breaches}, 0.9))
                elif r.status_code == 404:
                    out.findings.append(Finding("hibp", "breaches", {"count": 0, "breaches": []}, 0.95))
                else:
                    out.findings.append(Finding("hibp", "error", {"status": r.status_code}, 0.1))
        except Exception as e:
            out.findings.append(Finding("hibp", "error", {"error": str(e)}, 0.1))
    else:
        out.findings.append(Finding("hibp", "source_unavailable", {"reason": "no api key"}, 0.0))

    return out


register(Module(
    key="email",
    name="Email intelligence",
    subject_types=["email"],
    description="Syntax, domain, MX/SPF/DMARC, HIBP breach exposure.",
    run=run,
))
