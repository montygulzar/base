"""Subdomain takeover detection.

For each sub-host in the investigation (domain entities), resolve CNAME
and check if the CNAME target points to a service known to allow
takeover when unused (GitHub Pages, Heroku, AWS S3, Azure, Shopify,
Readme.io, Fastly, Netlify, ...). Flags candidates to verify.
"""
from __future__ import annotations
import asyncio
import dns.asyncresolver
from sqlalchemy import select
from ..db import SessionLocal
from ..models import Entity
from ..utils.validators import is_domain
from .base import Module, Finding, CollectionResult, RunContext, register

RESOLVER = dns.asyncresolver.Resolver()
RESOLVER.lifetime = 5.0

# host fragment -> provider
TAKEOVER_SIGS: dict[str, str] = {
    "github.io":            "github_pages",
    "herokuapp.com":        "heroku",
    "herokudns.com":        "heroku",
    "s3.amazonaws.com":     "aws_s3",
    "s3-website":           "aws_s3",
    "cloudapp.net":         "azure",
    "azurewebsites.net":    "azure",
    "trafficmanager.net":   "azure",
    "cloudfront.net":       "aws_cloudfront",
    "fastly.net":           "fastly",
    "readme.io":            "readme",
    "shopify.com":          "shopify",
    "myshopify.com":        "shopify",
    "cname.vercel-dns.com": "vercel",
    "netlify.app":          "netlify",
    "netlify.com":          "netlify",
    "pantheonsite.io":      "pantheon",
    "wordpress.com":        "wordpress",
    "surge.sh":             "surge",
    "zendesk.com":          "zendesk",
    "helpscoutdocs.com":    "helpscout",
    "ghost.io":             "ghost",
    "statuspage.io":        "statuspage",
    "unbouncepages.com":    "unbounce",
    "launchrock.com":       "launchrock",
    "intercom.help":        "intercom",
    "freshdesk.com":        "freshdesk",
    "tumblr.com":           "tumblr",
    "webflow.io":           "webflow",
    "bitbucket.io":         "bitbucket",
    "cargocollective.com":  "cargo",
    "wufoo.com":            "wufoo",
    "pingdom.com":          "pingdom",
}


async def _cname(host: str) -> str | None:
    try:
        a = await RESOLVER.resolve(host, "CNAME")
        return str(a[0].target).rstrip(".").lower()
    except Exception:
        return None


async def _a(host: str) -> list[str]:
    try:
        a = await RESOLVER.resolve(host, "A")
        return [r.to_text() for r in a]
    except Exception:
        return []


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    async with SessionLocal() as db:
        ents = (await db.execute(
            select(Entity).where(Entity.investigation_id == ctx.investigation_id,
                                 Entity.type == "domain")
        )).scalars().all()
    hosts = sorted({e.value for e in ents if is_domain(e.value)})
    if not hosts:
        out.findings.append(Finding("takeover", "no_domains", {}, 0.3))
        return out

    sem = asyncio.Semaphore(24)
    async def check(h: str):
        async with sem:
            cname = await _cname(h)
            ips = await _a(h) if not cname else []
            provider = None
            for frag, name in TAKEOVER_SIGS.items():
                if cname and frag in cname:
                    provider = name
                    break
            return {"host": h, "cname": cname, "a_records": ips, "provider": provider,
                    "nxdomain_or_empty": (cname is None and not ips)}

    results = await asyncio.gather(*[check(h) for h in hosts[:300]])
    candidates = [r for r in results if r["provider"] and r["nxdomain_or_empty"]]
    pointers = [r for r in results if r["provider"]]
    out.findings.append(Finding("takeover", "scan",
                                {"checked": len(results),
                                 "with_known_provider": len(pointers),
                                 "candidates": candidates,
                                 "all_pointers": pointers[:100]},
                                0.9 if candidates else 0.5))
    return out


register(Module(
    key="takeover",
    name="Subdomain takeover check",
    subject_types=["domain", "ip", "url", "email", "username", "company",
                   "media", "document", "phone"],
    description="Resolves every domain entity's CNAME + flags known-provider dangles.",
    run=run,
))
