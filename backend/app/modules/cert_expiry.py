"""Certificate expiry monitor — flag TLS certs expiring soon."""
from __future__ import annotations
import ssl
import socket
from datetime import datetime, timezone
from ..utils.validators import is_domain, normalise_domain
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


def _cert(host: str) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
        na = cert.get("notAfter")
        dt = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return {"not_after": na, "expires_at": dt.isoformat(),
                "days_remaining": (dt - datetime.now(tz=timezone.utc)).days,
                "subject": dict(x[0] for x in cert.get("subject", [])),
                "issuer": dict(x[0] for x in cert.get("issuer", []))}
    except Exception as e:
        return {"error": str(e)[:200]}


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    d = normalise_domain(subject)
    if not is_domain(d):
        out.findings.append(Finding("cert_expiry", "invalid_input", {"input": subject}, 0.1))
        return out
    import asyncio
    loop = asyncio.get_running_loop()
    info = await loop.run_in_executor(None, _cert, d)
    out.entities.append(Entity("domain", d, {}, 0.9))
    verdict = "ok"
    days = info.get("days_remaining")
    if "error" not in info:
        if days is not None and days < 0:
            verdict = "expired"
        elif days is not None and days < 14:
            verdict = "expiring_very_soon"
        elif days is not None and days < 30:
            verdict = "expiring_soon"
    out.findings.append(Finding("cert_expiry", "status",
                                {"domain": d, **info, "verdict": verdict}, 0.95))
    return out


register(Module(
    key="cert_expiry",
    name="Cert expiry monitor",
    subject_types=["domain"],
    description="Flags TLS certs expired / expiring within 14 or 30 days.",
    run=run,
))
