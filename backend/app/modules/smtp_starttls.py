"""SMTP STARTTLS capability check.

For each MX host on 25, read the banner, send EHLO, look for STARTTLS
in the response. Classifies the mail path as cleartext / opportunistic
/ enforced_unknown (we don't attempt MTA-STS policy fetch here; that
belongs in a dedicated module).
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


async def _probe(host: str) -> dict:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, 25), timeout=6)
    except Exception as e:
        return {"host": host, "error": str(e)[:200]}
    out: dict = {"host": host}
    try:
        banner = (await asyncio.wait_for(reader.readline(), timeout=4)).decode(errors="replace").strip()
        out["banner"] = banner
        writer.write(b"EHLO base-osint.local\r\n"); await writer.drain()
        buf = []
        for _ in range(16):
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
        out["starttls"] = any("STARTTLS" in l.upper() for l in buf)
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
        out.findings.append(Finding("smtp_starttls", "invalid_input", {"input": subject}, 0.1))
        return out
    mx = await _mx(d)
    out.entities.append(Entity("domain", d, {}, 0.9))
    if not mx:
        out.findings.append(Finding("smtp_starttls", "no_mx", {"domain": d}, 0.4))
        return out
    results = await asyncio.gather(*[_probe(h) for h in mx[:3]])
    any_cleartext = any(not r.get("starttls") and "error" not in r for r in results)
    verdict = "cleartext_some_hosts" if any_cleartext else "starttls_all_hosts"
    out.findings.append(Finding("smtp_starttls", "probe",
                                {"domain": d, "mx": mx, "results": results,
                                 "verdict": verdict}, 0.95))
    return out


register(Module(
    key="smtp_starttls",
    name="SMTP STARTTLS capability",
    subject_types=["domain", "email"],
    description="Reports which MX hosts advertise STARTTLS vs cleartext.",
    run=run,
))
