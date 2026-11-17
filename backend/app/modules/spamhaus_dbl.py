"""Spamhaus DBL (domain blocklist) check via DNS."""
from __future__ import annotations
import dns.asyncresolver
from ..utils.validators import is_domain, normalise_domain
from .base import Module, Finding, Entity, CollectionResult, RunContext, register

RESOLVER = dns.asyncresolver.Resolver()
RESOLVER.lifetime = 4.0


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    d = normalise_domain(subject)
    if not is_domain(d):
        out.findings.append(Finding("spamhaus_dbl", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("domain", d, {}, 0.9))
    for bl in ("dbl.spamhaus.org", "multi.surbl.org"):
        q = f"{d}.{bl}"
        try:
            a = await RESOLVER.resolve(q, "A")
            out.findings.append(Finding("spamhaus_dbl", "listed",
                                        {"domain": d, "bl": bl,
                                         "codes": [r.to_text() for r in a]},
                                        0.95))
        except Exception:
            out.findings.append(Finding("spamhaus_dbl", "clean",
                                        {"domain": d, "bl": bl}, 0.9))
    return out


register(Module(
    key="spamhaus_dbl",
    name="Spamhaus DBL + SURBL",
    subject_types=["domain"],
    description="DNS-based domain blocklist check against DBL + SURBL.",
    run=run,
))
