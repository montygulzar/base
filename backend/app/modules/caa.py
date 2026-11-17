"""CAA record check — Certificate Authority Authorization (RFC 8659).

Reports which CAs the domain authorizes to issue certs, and flags
'no CAA record' (anyone can issue) or 'issue=\";\"' (deny).
"""
from __future__ import annotations
import dns.asyncresolver
from ..utils.validators import is_domain, normalise_domain
from .base import Module, Finding, Entity, CollectionResult, RunContext, register

RESOLVER = dns.asyncresolver.Resolver()
RESOLVER.lifetime = 5.0


async def _caa(name: str) -> list[str]:
    try:
        a = await RESOLVER.resolve(name, "CAA")
        return [r.to_text() for r in a]
    except Exception:
        return []


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    d = normalise_domain(subject)
    if not is_domain(d):
        out.findings.append(Finding("caa", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("domain", d, {}, 0.9))
    records = await _caa(d)
    issuers: list[str] = []
    denies: list[str] = []
    wildcards: list[str] = []
    for r in records:
        parts = r.split()
        if len(parts) >= 3:
            tag = parts[1]
            val = " ".join(parts[2:]).strip('"')
            if tag == "issue":
                (denies if val == ";" else issuers).append(val)
            elif tag == "issuewild":
                wildcards.append(val)
    out.findings.append(Finding("caa", "record",
                                {"domain": d, "raw": records,
                                 "issuers": issuers, "wildcards": wildcards,
                                 "denies": denies,
                                 "verdict": ("missing_caa" if not records else
                                             "allow_all" if not issuers and not denies else
                                             "constrained")},
                                0.95))
    return out


register(Module(
    key="caa",
    name="CAA record",
    subject_types=["domain"],
    description="Certification Authority Authorization DNS lookup.",
    run=run,
))
