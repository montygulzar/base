"""Certificate pivot via crt.sh.

Given a domain, fetch its latest certs, pull every subject common name and
SAN across those certs, and emit the set as related domains. Reveals
infrastructure shared under one certificate.
"""
from __future__ import annotations
import re
import httpx
from ..utils.validators import normalise_domain, is_domain
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    d = normalise_domain(subject)
    if not is_domain(d):
        out.findings.append(Finding("cert_pivot", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("domain", d, {}, 0.9))
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            r = await c.get(f"https://crt.sh/?q={d}&output=json", timeout=25)
            if r.status_code != 200:
                out.findings.append(Finding("cert_pivot", "http_error",
                                            {"status": r.status_code}, 0.1))
                return out
            certs = r.json() if r.text.strip() else []
            seen: set[str] = set()
            cert_summaries = []
            for row in certs[:100]:
                issuer = row.get("issuer_name")
                cn = row.get("common_name") or ""
                names = [n.strip().lower().lstrip("*.") for n in (row.get("name_value") or "").splitlines() if n.strip()]
                cert_summaries.append({
                    "id": row.get("id"), "issuer": issuer, "cn": cn, "names_count": len(names),
                    "not_before": row.get("not_before"), "not_after": row.get("not_after"),
                })
                for n in names:
                    if "@" in n or " " in n:
                        continue
                    if is_domain(n):
                        seen.add(n)
            out.findings.append(Finding("cert_pivot", "certs",
                                        {"count": len(certs), "sample": cert_summaries[:25]}, 0.9))
            out.findings.append(Finding("cert_pivot", "domains",
                                        {"count": len(seen), "domains": sorted(seen)[:500]}, 0.85))
            for n in list(seen)[:500]:
                if n == d:
                    continue
                out.entities.append(Entity("domain", n, {"from": "cert_pivot"}, 0.75))
                out.relationships.append(Relationship("domain", n, "domain", d,
                                                      "shares_cert_with", "crt.sh", 0.75))
        except Exception as e:
            out.findings.append(Finding("cert_pivot", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="cert_pivot",
    name="Certificate pivot (crt.sh)",
    subject_types=["domain"],
    description="Pulls every cert for a domain and expands all CN/SAN names.",
    run=run,
))
