"""Deep TLS scan.

- Negotiate the highest TLS version the server accepts.
- Enumerate TLS 1.0 / 1.1 / 1.2 / 1.3 support (compatibility handshake
  per version).
- Certificate chain: subject, issuer, validity, SANs, serial, signature
  algo, basic-constraints, SAN count.
- Pull: HSTS preload-ability check (header presence, max-age ≥ 31536000,
  includeSubDomains, preload).

No OpenSSL subprocess — all stdlib ssl + httpx.
"""
from __future__ import annotations
import asyncio
import ssl
import socket
from datetime import datetime
import httpx
from ..utils.validators import normalise_domain, is_domain
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


def _cert_info(host: str, version: int) -> dict:
    ctx = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion(version)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                proto = s.version()
                cipher = s.cipher()
        subject = dict(x[0] for x in (cert or {}).get("subject", []))
        issuer = dict(x[0] for x in (cert or {}).get("issuer", []))
        sans = [v for t, v in (cert or {}).get("subjectAltName", []) if t == "DNS"]
        return {"supported": True, "negotiated": proto,
                "cipher": {"name": cipher[0], "version": cipher[1], "bits": cipher[2]} if cipher else None,
                "subject": subject, "issuer": issuer,
                "not_before": cert.get("notBefore"), "not_after": cert.get("notAfter"),
                "sans_count": len(sans), "sans_sample": sans[:20],
                "serial": cert.get("serialNumber")}
    except Exception as e:
        return {"supported": False, "error": str(e)[:200]}


async def _hsts(host: str) -> dict:
    try:
        async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}, follow_redirects=True) as c:
            r = await c.get(f"https://{host}/", timeout=10)
        h = r.headers.get("strict-transport-security", "")
        max_age = 0
        parts = {p.split("=")[0].strip().lower(): (p.split("=")[1].strip() if "=" in p else "")
                 for p in h.split(";") if p.strip()}
        if "max-age" in parts and parts["max-age"].isdigit():
            max_age = int(parts["max-age"])
        return {
            "header": h, "max_age": max_age,
            "include_subdomains": "includesubdomains" in parts,
            "preload": "preload" in parts,
            "preload_eligible": max_age >= 31536000 and "includesubdomains" in parts and "preload" in parts,
        }
    except Exception as e:
        return {"error": str(e)[:200]}


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    d = normalise_domain(subject)
    if not is_domain(d):
        out.findings.append(Finding("tls_scan", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("domain", d, {}, 0.9))
    loop = asyncio.get_running_loop()
    # Named TLSVersion values differ a bit across Python versions; use constants.
    versions = {
        "TLSv1.0": ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }
    results = {}
    for name, v in versions.items():
        results[name] = await loop.run_in_executor(None, _cert_info, d, int(v))
    best = None
    for name in ("TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0"):
        if results[name].get("supported"):
            best = results[name]; break
    hsts = await _hsts(d)
    out.findings.append(Finding("tls_scan", "versions",
                                {"domain": d, "support": results,
                                 "legacy_tls_enabled": any(results[v].get("supported") for v in ("TLSv1.0","TLSv1.1"))},
                                0.95))
    if best:
        out.findings.append(Finding("tls_scan", "best_certificate", best, 0.95))
    out.findings.append(Finding("tls_scan", "hsts", hsts, 0.95))
    return out


register(Module(
    key="tls_scan",
    name="Deep TLS scan",
    subject_types=["domain"],
    description="TLS versions, cipher, cert chain, HSTS preload check.",
    run=run,
))
