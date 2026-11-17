"""Historic WHOIS via archive.org.

Pulls snapshots of whois.com/whois/<domain> from the Wayback Machine
CDX API and reports available snapshot URLs. Analysts click through.
"""
from __future__ import annotations
import httpx
from ..utils.validators import is_domain, normalise_domain
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    d = normalise_domain(subject)
    if not is_domain(d):
        out.findings.append(Finding("archive_whois", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("domain", d, {}, 0.9))
    target = f"whois.com/whois/{d}"
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            r = await c.get(
                "https://web.archive.org/cdx/search/cdx",
                params={"url": target, "output": "json", "collapse": "timestamp:6",
                        "fl": "timestamp,original", "limit": 50},
                timeout=25,
            )
            if r.status_code != 200:
                out.findings.append(Finding("archive_whois", "http_error",
                                            {"status": r.status_code}, 0.1))
                return out
            rows = r.json()
            snaps = []
            if rows and len(rows) > 1:
                for ts, orig in rows[1:]:
                    snaps.append({"ts": ts,
                                  "url": f"https://web.archive.org/web/{ts}/{orig}"})
            out.findings.append(Finding("archive_whois", "snapshots",
                                        {"target": target, "count": len(snaps),
                                         "snapshots": snaps}, 0.9 if snaps else 0.3))
            for s in snaps[:5]:
                out.entities.append(Entity("url", s["url"], {"kind": "archive_whois_snapshot"}, 0.7))
        except Exception as e:
            out.findings.append(Finding("archive_whois", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="archive_whois",
    name="Historic WHOIS (archive.org)",
    subject_types=["domain"],
    description="Wayback snapshots of whois.com/whois/<domain>.",
    run=run,
))
