"""Domain intelligence module.

Collects, in order: WHOIS / RDAP, DNS (A/AAAA/MX/NS/TXT/SPF/DMARC),
Certificate Transparency (crt.sh — no key), passive subdomain discovery,
HTTP security headers, tech fingerprint. Optional integrations
(VirusTotal, SecurityTrails, urlscan, Shodan) are invoked if configured.
"""
from __future__ import annotations
import asyncio
import ssl
import socket
from datetime import datetime
import httpx
import dns.asyncresolver
from ..utils.validators import normalise_domain, is_domain
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register
from ..config import get_settings

RESOLVER = dns.asyncresolver.Resolver()
RESOLVER.lifetime = 8.0


async def _dns(domain: str, rtype: str) -> list[str]:
    try:
        a = await RESOLVER.resolve(domain, rtype)
        return [r.to_text().strip('"') for r in a]
    except Exception:
        return []


async def _whois(domain: str) -> dict:
    loop = asyncio.get_running_loop()
    try:
        import whois  # lazy
        w = await loop.run_in_executor(None, whois.whois, domain)
        return {k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in dict(w).items() if v and not callable(v)}
    except Exception as e:
        return {"error": str(e)}


async def _crtsh(client: httpx.AsyncClient, domain: str) -> list[str]:
    try:
        r = await client.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20)
        if r.status_code != 200:
            return []
        subs = set()
        for row in r.json():
            for name in (row.get("name_value") or "").splitlines():
                name = name.strip().lower().lstrip("*.")
                if "@" in name or " " in name:
                    continue
                if name.endswith("." + domain) or name == domain:
                    if is_domain(name):
                        subs.add(name)
        return sorted(subs)
    except Exception:
        return []


async def _http_probe(client: httpx.AsyncClient, domain: str) -> dict:
    for scheme in ("https", "http"):
        try:
            r = await client.get(f"{scheme}://{domain}", timeout=10, follow_redirects=True)
            tech = []
            server = r.headers.get("server", "")
            if server:
                tech.append(server)
            xpow = r.headers.get("x-powered-by", "")
            if xpow:
                tech.append(xpow)
            return {
                "scheme": scheme,
                "status": r.status_code,
                "final_url": str(r.url),
                "server": server,
                "x-powered-by": xpow,
                "headers": dict(r.headers),
                "security_headers": {
                    "hsts": r.headers.get("strict-transport-security"),
                    "csp": r.headers.get("content-security-policy"),
                    "x-frame-options": r.headers.get("x-frame-options"),
                    "x-content-type-options": r.headers.get("x-content-type-options"),
                    "referrer-policy": r.headers.get("referrer-policy"),
                },
                "technology": tech,
            }
        except Exception:
            continue
    return {"error": "unreachable"}


def _cert(domain: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as s:
                c = s.getpeercert()
        subject = dict(x[0] for x in c.get("subject", []))
        issuer = dict(x[0] for x in c.get("issuer", []))
        return {"subject": subject, "issuer": issuer, "not_before": c.get("notBefore"), "not_after": c.get("notAfter")}
    except Exception as e:
        return {"error": str(e)}


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    s = get_settings()
    out = CollectionResult()
    d = normalise_domain(subject)
    if not is_domain(d):
        out.findings.append(Finding("domain", "invalid_input", {"input": subject}, 0.1))
        return out

    out.entities.append(Entity("domain", d, {"root": True}, 0.95))

    async with httpx.AsyncClient(timeout=s.HTTP_TIMEOUT_SECONDS, headers={"user-agent": "base-osint/0.1"}) as client:
        whois_data, a, aaaa, mx, ns, txt, subs, http = await asyncio.gather(
            _whois(d),
            _dns(d, "A"),
            _dns(d, "AAAA"),
            _dns(d, "MX"),
            _dns(d, "NS"),
            _dns(d, "TXT"),
            _crtsh(client, d),
            _http_probe(client, d),
        )
        dmarc = await _dns(f"_dmarc.{d}", "TXT")

    cert = _cert(d)

    out.findings.append(Finding("whois", "whois", whois_data, 0.85 if "error" not in whois_data else 0.2))
    out.findings.append(Finding("dns", "a", {"records": a}, 0.95 if a else 0.2))
    out.findings.append(Finding("dns", "aaaa", {"records": aaaa}, 0.95 if aaaa else 0.2))
    out.findings.append(Finding("dns", "mx", {"records": mx}, 0.95 if mx else 0.2))
    out.findings.append(Finding("dns", "ns", {"records": ns}, 0.95 if ns else 0.2))
    out.findings.append(Finding("dns", "txt", {"records": txt}, 0.9 if txt else 0.2))
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    out.findings.append(Finding("dns", "spf", {"records": spf}, 0.9 if spf else 0.2))
    out.findings.append(Finding("dns", "dmarc", {"records": dmarc}, 0.9 if dmarc else 0.2))
    out.findings.append(Finding("crt.sh", "ct_subdomains", {"subdomains": subs, "count": len(subs)}, 0.8))
    out.findings.append(Finding("http", "probe", http, 0.9 if "error" not in http else 0.2))
    out.findings.append(Finding("tls", "certificate", cert, 0.9 if "error" not in cert else 0.2))

    for ip in a + aaaa:
        out.entities.append(Entity("ip", ip, {"family": "v6" if ":" in ip else "v4"}, 0.9))
        out.relationships.append(Relationship("domain", d, "ip", ip, "resolves_to", "dns", 0.95))
    for rec in mx:
        parts = rec.split()
        host = (parts[-1] if parts else rec).rstrip(".")
        if is_domain(host):
            out.entities.append(Entity("domain", host, {"role": "mx"}, 0.8))
            out.relationships.append(Relationship("domain", d, "domain", host, "mx_for", "dns", 0.9))
    for rec in ns:
        host = rec.rstrip(".")
        if is_domain(host):
            out.entities.append(Entity("domain", host, {"role": "ns"}, 0.8))
            out.relationships.append(Relationship("domain", d, "domain", host, "ns_for", "dns", 0.9))
    for sub in subs[:200]:
        if sub != d:
            out.entities.append(Entity("domain", sub, {"from": "crt.sh"}, 0.75))
            out.relationships.append(Relationship("domain", sub, "domain", d, "subdomain_of", "crt.sh", 0.85))

    # --- optional enrichments ---
    if s.VIRUSTOTAL_API_KEY:
        try:
            async with httpx.AsyncClient() as c:
                r = await c.get(f"https://www.virustotal.com/api/v3/domains/{d}",
                                headers={"x-apikey": s.VIRUSTOTAL_API_KEY}, timeout=15)
                if r.status_code == 200:
                    out.findings.append(Finding("virustotal", "domain", r.json().get("data", {}), 0.85))
        except Exception as e:
            out.findings.append(Finding("virustotal", "error", {"error": str(e)}, 0.1))
    else:
        out.findings.append(Finding("virustotal", "source_unavailable", {"reason": "no api key"}, 0.0))

    if s.SECURITYTRAILS_API_KEY:
        try:
            async with httpx.AsyncClient() as c:
                r = await c.get(f"https://api.securitytrails.com/v1/domain/{d}/subdomains",
                                headers={"APIKEY": s.SECURITYTRAILS_API_KEY}, timeout=15)
                if r.status_code == 200:
                    data = r.json()
                    extra = [f"{x}.{d}" for x in data.get("subdomains", [])]
                    out.findings.append(Finding("securitytrails", "subdomains",
                                                {"count": len(extra), "subdomains": extra[:500]}, 0.85))
                    for sub in extra[:500]:
                        out.entities.append(Entity("domain", sub, {"from": "securitytrails"}, 0.8))
                        out.relationships.append(Relationship("domain", sub, "domain", d, "subdomain_of", "securitytrails", 0.85))
        except Exception as e:
            out.findings.append(Finding("securitytrails", "error", {"error": str(e)}, 0.1))

    return out


register(Module(
    key="domain",
    name="Domain intelligence",
    subject_types=["domain", "url"],
    description="WHOIS, DNS, CT, cert, headers, subdomains, enrichments.",
    run=run,
))
