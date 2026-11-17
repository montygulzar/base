"""SMTP banner grab across a domain's MX servers.

Connects to each MX host on port 25 (and 587 fallback), reads the
greeting, sends EHLO base-osint, reports the returned extensions. No
DATA phase, no delivery.
"""
from __future__ import annotations
import asyncio
import dns.asyncresolver
from ..utils.validators import is_domain, normalise_domain
from .base import Module, Finding, Entity, CollectionResult, RunContext, register

RESOLVER = dns.asyncresolver.Resolver()
RESOLVER.lifetime = 5.0


async def _mx(domain: str) -> list[str]:
    try:
        a = await RESOLVER.resolve(domain, "MX")
        return [r.to_text().split()[-1].rstrip(".") for r in a]
    except Exception:
        return []


async def _probe(host: str, port: int) -> dict:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=6)
    except Exception as e:
        return {"host": host, "port": port, "error": str(e)[:200]}
    out: dict = {"host": host, "port": port}
    try:
        banner = (await asyncio.wait_for(reader.readline(), timeout=4)).decode(errors="replace").strip()
        out["banner"] = banner
        writer.write(b"EHLO base-osint.local\r\n")
        await writer.drain()
        buf = []
        for _ in range(12):
            try:
                line = (await asyncio.wait_for(reader.readline(), timeout=3)).decode(errors="replace").strip()
            except asyncio.TimeoutError:
                break
            if not line:
                break
            buf.append(line)
            if line[:3].isdigit() and line[3:4] == " ":
                break
        out["ehlo"] = buf
        writer.write(b"QUIT\r\n"); await writer.drain()
    except Exception as e:
        out["error"] = str(e)[:200]
    finally:
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass
    return out


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    d = normalise_domain(subject.split("@")[-1]) if "@" in (subject or "") else normalise_domain(subject)
    if not is_domain(d):
        out.findings.append(Finding("smtp_banner", "invalid_input", {"input": subject}, 0.1))
        return out
    mx = await _mx(d)
    out.entities.append(Entity("domain", d, {}, 0.9))
    out.findings.append(Finding("smtp_banner", "mx", {"domain": d, "mx": mx},
                                0.9 if mx else 0.3))
    results = []
    for host in mx[:3]:
        r25 = await _probe(host, 25)
        results.append(r25)
        if "error" in r25:
            results.append(await _probe(host, 587))
    out.findings.append(Finding("smtp_banner", "probes",
                                {"count": len(results), "results": results}, 0.9))
    return out


register(Module(
    key="smtp_banner",
    name="SMTP banner",
    subject_types=["domain", "email"],
    description="Grabs SMTP banners + EHLO extensions from MX hosts.",
    run=run,
))
