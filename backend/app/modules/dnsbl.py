"""DNSBL multi-blocklist check.

Does reverse-octet DNS lookups against 12 well-known DNSBLs for the
subject IP. Keyless. Reports which lists responded with a positive A
record (= listed).
"""
from __future__ import annotations
import asyncio
import ipaddress
import dns.asyncresolver
from ..utils.validators import is_ip, is_private_ip
from .base import Module, Finding, Entity, CollectionResult, RunContext, register

RESOLVER = dns.asyncresolver.Resolver()
RESOLVER.lifetime = 4.0

DNSBLS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "cbl.abuseat.org",
    "dnsbl.sorbs.net",
    "all.s5h.net",
    "psbl.surriel.com",
    "dnsbl-1.uceprotect.net",
    "truncate.gbudb.net",
    "ubl.unsubscore.com",
    "rbl.interserver.net",
    "spam.dnsbl.anonmails.de",
]


async def _check(ip: str, bl: str) -> dict:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return {"bl": bl, "listed": False, "error": "invalid ip"}
    if a.version != 4:
        return {"bl": bl, "listed": False, "note": "ipv4 only"}
    reversed_ = ".".join(reversed(ip.split(".")))
    q = f"{reversed_}.{bl}"
    try:
        ans = await RESOLVER.resolve(q, "A")
        return {"bl": bl, "listed": True, "answer": [r.to_text() for r in ans]}
    except Exception:
        return {"bl": bl, "listed": False}


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    if not is_ip(v):
        out.findings.append(Finding("dnsbl", "invalid_input", {"input": subject}, 0.1))
        return out
    if is_private_ip(v):
        out.findings.append(Finding("dnsbl", "private_address", {"ip": v}, 1.0))
        return out
    out.entities.append(Entity("ip", v, {}, 0.95))
    sem = asyncio.Semaphore(12)

    async def guarded(bl):
        async with sem:
            return await _check(v, bl)

    results = await asyncio.gather(*[guarded(bl) for bl in DNSBLS])
    listed = [r for r in results if r.get("listed")]
    out.findings.append(Finding("dnsbl", "scan",
                                {"checked": len(DNSBLS), "listed_count": len(listed),
                                 "listed": listed, "all_results": results},
                                0.95 if listed else 0.8))
    return out


register(Module(
    key="dnsbl",
    name="DNSBL check",
    subject_types=["ip"],
    description="12-blocklist DNSBL check for an IPv4.",
    run=run,
))
