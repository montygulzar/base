"""CertSpotter (SSLMate) — Certificate Transparency, keyless free tier."""
from __future__ import annotations
import httpx
from ..utils.validators import is_domain, normalise_domain
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    d = normalise_domain(subject)
    if not is_domain(d):
        out.findings.append(Finding("certspotter", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("domain", d, {}, 0.9))
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            r = await c.get(
                f"https://api.certspotter.com/v1/issuances",
                params={"domain": d, "include_subdomains": "true",
                        "expand": "dns_names,issuer,cert"},
                timeout=25,
            )
            if r.status_code != 200:
                out.findings.append(Finding("certspotter", "http_error",
                                            {"status": r.status_code, "body": r.text[:200]}, 0.1))
                return out
            issuances = r.json()
            names = set()
            issuers: dict[str, int] = {}
            for row in issuances[:200]:
                for n in row.get("dns_names") or []:
                    n = n.lower().lstrip("*.")
                    if "@" in n or " " in n:
                        continue
                    if is_domain(n):
                        names.add(n)
                iss = (row.get("issuer") or {}).get("name") or ""
                if iss:
                    issuers[iss] = issuers.get(iss, 0) + 1
            out.findings.append(Finding("certspotter", "issuances",
                                        {"count": len(issuances),
                                         "unique_names": len(names),
                                         "issuers_hist": issuers}, 0.9))
            for n in sorted(names)[:500]:
                if n == d:
                    continue
                out.entities.append(Entity("domain", n, {"from": "certspotter"}, 0.75))
                out.relationships.append(Relationship("domain", n, "domain", d,
                                                      "subdomain_of", "certspotter", 0.85))
        except Exception as e:
            out.findings.append(Finding("certspotter", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="certspotter",
    name="CertSpotter (CT)",
    subject_types=["domain"],
    description="SSLMate CertSpotter v1 issuances (keyless).",
    run=run,
))
