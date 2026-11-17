"""DNSSEC posture + AXFR attempt.

- DNSSEC: query DS / DNSKEY / RRSIG. If present, chain is at least
  advertised. The module doesn't do full validation (needs a recursive
  resolver with DNSSEC enabled); it reports presence + algorithms.
- AXFR: for every NS of the domain, attempt an AXFR. Almost always
  refused — the finding is the attempt + the response.
"""
from __future__ import annotations
import asyncio
import dns.asyncresolver
import dns.query
import dns.zone
import dns.exception
from ..utils.validators import is_domain, normalise_domain
from .base import Module, Finding, Entity, CollectionResult, RunContext, register

RESOLVER = dns.asyncresolver.Resolver()
RESOLVER.lifetime = 5.0


async def _rr(name: str, rtype: str) -> list[str]:
    try:
        a = await RESOLVER.resolve(name, rtype)
        return [r.to_text() for r in a]
    except Exception:
        return []


def _axfr(ns: str, zone: str) -> dict:
    try:
        x = dns.zone.from_xfr(dns.query.xfr(ns, zone, lifetime=5.0))
        return {"success": True, "ns": ns, "record_count": len(list(x.iterate_rdatasets()))}
    except dns.exception.DNSException as e:
        return {"success": False, "ns": ns, "error": str(e)[:200]}
    except Exception as e:
        return {"success": False, "ns": ns, "error": str(e)[:200]}


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    d = normalise_domain(subject)
    if not is_domain(d):
        out.findings.append(Finding("dnssec_axfr", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("domain", d, {}, 0.9))

    ns, ds, dnskey = await asyncio.gather(
        _rr(d, "NS"), _rr(d, "DS"), _rr(d, "DNSKEY"),
    )
    out.findings.append(Finding("dnssec_axfr", "dnssec",
                                {"ns_count": len(ns), "ds": ds, "dnskey": dnskey,
                                 "has_dnssec": bool(ds or dnskey)},
                                0.9))

    loop = asyncio.get_running_loop()
    axfrs = await asyncio.gather(*[
        loop.run_in_executor(None, _axfr, n.rstrip("."), d) for n in ns
    ])
    successful = [a for a in axfrs if a.get("success")]
    out.findings.append(Finding("dnssec_axfr", "axfr_attempts",
                                {"attempted": len(axfrs), "successful": successful,
                                 "results": axfrs},
                                0.95 if successful else 0.5))
    return out


register(Module(
    key="dnssec_axfr",
    name="DNSSEC + AXFR",
    subject_types=["domain"],
    description="DNSSEC presence check + AXFR zone-transfer probe per NS.",
    run=run,
))
