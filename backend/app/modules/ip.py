"""IP and network intelligence."""
from __future__ import annotations
import asyncio
import socket
import httpx
from ..utils.validators import is_ip, is_private_ip
from ..config import get_settings
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


async def _rdns(ip: str) -> str | None:
    loop = asyncio.get_running_loop()
    try:
        return (await loop.run_in_executor(None, socket.gethostbyaddr, ip))[0]
    except Exception:
        return None


async def _rdap(client: httpx.AsyncClient, ip: str) -> dict:
    try:
        r = await client.get(f"https://rdap.arin.net/registry/ip/{ip}", timeout=15)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        return {"error": str(e)}
    return {}


async def _bgpview(client: httpx.AsyncClient, ip: str) -> dict:
    try:
        r = await client.get(f"https://api.bgpview.io/ip/{ip}", timeout=15)
        if r.status_code == 200:
            return (r.json() or {}).get("data", {})
    except Exception as e:
        return {"error": str(e)}
    return {}


async def _ripestat(client: httpx.AsyncClient, ip: str) -> dict:
    try:
        r = await client.get(f"https://stat.ripe.net/data/network-info/data.json?resource={ip}", timeout=15)
        if r.status_code == 200:
            return (r.json() or {}).get("data", {})
    except Exception as e:
        return {"error": str(e)}
    return {}


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    s = get_settings()
    out = CollectionResult()
    ip = subject.strip()
    if not is_ip(ip):
        out.findings.append(Finding("ip", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("ip", ip, {"private": is_private_ip(ip)}, 0.95))

    if is_private_ip(ip):
        out.findings.append(Finding("ip", "private_address", {"ip": ip}, 1.0))
        return out

    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as client:
        rdns, rdap, bgp, ripe = await asyncio.gather(
            _rdns(ip), _rdap(client, ip), _bgpview(client, ip), _ripestat(client, ip)
        )

        out.findings.append(Finding("rdns", "ptr", {"host": rdns}, 0.85 if rdns else 0.2))
        out.findings.append(Finding("rdap", "rdap", rdap, 0.9 if rdap else 0.2))
        out.findings.append(Finding("bgpview", "asn_info", bgp, 0.85 if bgp else 0.2))
        out.findings.append(Finding("ripestat", "network_info", ripe, 0.85 if ripe else 0.2))

        for pfx in (bgp.get("prefixes") or []):
            asn = (pfx.get("asn") or {}).get("asn")
            name = (pfx.get("asn") or {}).get("name")
            if asn:
                v = f"AS{asn}"
                out.entities.append(Entity("asn", v, {"name": name}, 0.9))
                out.relationships.append(Relationship("ip", ip, "asn", v, "announced_by", "bgpview", 0.9))

        if s.SHODAN_API_KEY:
            try:
                r = await client.get(f"https://api.shodan.io/shodan/host/{ip}?key={s.SHODAN_API_KEY}", timeout=15)
                if r.status_code == 200:
                    j = r.json()
                    out.findings.append(Finding("shodan", "host", {
                        "org": j.get("org"), "asn": j.get("asn"), "isp": j.get("isp"),
                        "country": j.get("country_name"), "ports": j.get("ports"),
                        "hostnames": j.get("hostnames"), "tags": j.get("tags"),
                        "vulns": list((j.get("vulns") or {})) if isinstance(j.get("vulns"), dict) else j.get("vulns"),
                    }, 0.9))
                    for h in j.get("hostnames") or []:
                        out.entities.append(Entity("domain", h, {"from": "shodan"}, 0.8))
                        out.relationships.append(Relationship("domain", h, "ip", ip, "resolves_to", "shodan", 0.85))
            except Exception as e:
                out.findings.append(Finding("shodan", "error", {"error": str(e)}, 0.1))
        else:
            out.findings.append(Finding("shodan", "source_unavailable", {"reason": "no api key"}, 0.0))

        if s.GREYNOISE_API_KEY:
            try:
                r = await client.get(f"https://api.greynoise.io/v3/community/{ip}",
                                     headers={"key": s.GREYNOISE_API_KEY}, timeout=15)
                if r.status_code in (200, 404):
                    out.findings.append(Finding("greynoise", "community", r.json(), 0.85))
            except Exception as e:
                out.findings.append(Finding("greynoise", "error", {"error": str(e)}, 0.1))
        else:
            out.findings.append(Finding("greynoise", "source_unavailable", {"reason": "no api key"}, 0.0))

        if s.ABUSEIPDB_API_KEY:
            try:
                r = await client.get("https://api.abuseipdb.com/api/v2/check",
                                     params={"ipAddress": ip, "maxAgeInDays": 90},
                                     headers={"Key": s.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                                     timeout=15)
                if r.status_code == 200:
                    out.findings.append(Finding("abuseipdb", "reputation", (r.json() or {}).get("data", {}), 0.85))
            except Exception as e:
                out.findings.append(Finding("abuseipdb", "error", {"error": str(e)}, 0.1))
        else:
            out.findings.append(Finding("abuseipdb", "source_unavailable", {"reason": "no api key"}, 0.0))

        if s.IPINFO_TOKEN:
            try:
                r = await client.get(f"https://ipinfo.io/{ip}?token={s.IPINFO_TOKEN}", timeout=15)
                if r.status_code == 200:
                    out.findings.append(Finding("ipinfo", "geo", r.json(), 0.8))
            except Exception as e:
                out.findings.append(Finding("ipinfo", "error", {"error": str(e)}, 0.1))
        else:
            out.findings.append(Finding("ipinfo", "source_unavailable", {"reason": "no token"}, 0.0))

    if rdns:
        out.entities.append(Entity("domain", rdns, {"ptr": True}, 0.8))
        out.relationships.append(Relationship("ip", ip, "domain", rdns, "ptr_to", "rdns", 0.85))

    return out


register(Module(
    key="ip",
    name="IP & network intelligence",
    subject_types=["ip"],
    description="RDNS, RDAP, ASN, geo, reputation, service exposure.",
    run=run,
))
