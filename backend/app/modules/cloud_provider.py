"""Detect which cloud provider an IP belongs to.

Pulls each provider's published IP range JSON once per process and checks
the subject IP against every range. Returns provider, service, region.
"""
from __future__ import annotations
import ipaddress
import httpx
from ..utils.validators import is_ip, is_private_ip
from .base import Module, Finding, Entity, CollectionResult, RunContext, register

_cache: dict[str, list[tuple]] = {}


async def _aws(c: httpx.AsyncClient) -> list[tuple]:
    if "aws" in _cache:
        return _cache["aws"]
    out: list[tuple] = []
    try:
        r = await c.get("https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=25)
        if r.status_code == 200:
            j = r.json()
            for p in j.get("prefixes", []):
                try:
                    out.append((ipaddress.ip_network(p["ip_prefix"]), "AWS",
                                p.get("service"), p.get("region")))
                except Exception:
                    pass
            for p in j.get("ipv6_prefixes", []):
                try:
                    out.append((ipaddress.ip_network(p["ipv6_prefix"]), "AWS",
                                p.get("service"), p.get("region")))
                except Exception:
                    pass
    except Exception:
        pass
    _cache["aws"] = out
    return out


async def _gcp(c: httpx.AsyncClient) -> list[tuple]:
    if "gcp" in _cache:
        return _cache["gcp"]
    out: list[tuple] = []
    try:
        r = await c.get("https://www.gstatic.com/ipranges/cloud.json", timeout=25)
        if r.status_code == 200:
            for p in (r.json() or {}).get("prefixes", []):
                v = p.get("ipv4Prefix") or p.get("ipv6Prefix")
                if v:
                    try:
                        out.append((ipaddress.ip_network(v), "GCP",
                                    p.get("service"), p.get("scope")))
                    except Exception:
                        pass
    except Exception:
        pass
    _cache["gcp"] = out
    return out


async def _cloudflare(c: httpx.AsyncClient) -> list[tuple]:
    if "cloudflare" in _cache:
        return _cache["cloudflare"]
    out: list[tuple] = []
    try:
        r = await c.get("https://www.cloudflare.com/ips-v4", timeout=15)
        if r.status_code == 200:
            for ln in r.text.splitlines():
                ln = ln.strip()
                if ln:
                    try: out.append((ipaddress.ip_network(ln), "Cloudflare", None, None))
                    except Exception: pass
        r = await c.get("https://www.cloudflare.com/ips-v6", timeout=15)
        if r.status_code == 200:
            for ln in r.text.splitlines():
                ln = ln.strip()
                if ln:
                    try: out.append((ipaddress.ip_network(ln), "Cloudflare", None, None))
                    except Exception: pass
    except Exception:
        pass
    _cache["cloudflare"] = out
    return out


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    if not is_ip(v):
        out.findings.append(Finding("cloud_provider", "invalid_input", {"input": subject}, 0.1))
        return out
    if is_private_ip(v):
        out.findings.append(Finding("cloud_provider", "private_address", {"ip": v}, 1.0))
        return out
    out.entities.append(Entity("ip", v, {}, 0.95))
    ip_obj = ipaddress.ip_address(v)
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        ranges = []
        for loader in (_aws, _gcp, _cloudflare):
            ranges += await loader(c)
    hits = []
    for net, provider, service, region in ranges:
        if (ip_obj.version == 4 and net.version == 4) or (ip_obj.version == 6 and net.version == 6):
            if ip_obj in net:
                hits.append({"provider": provider, "service": service, "region": region,
                             "prefix": str(net)})
                if len(hits) >= 5:
                    break
    out.findings.append(Finding("cloud_provider", "lookup",
                                {"ip": v, "range_loaded": len(ranges), "hits": hits},
                                0.95 if hits else 0.6))
    return out


register(Module(
    key="cloud_provider",
    name="Cloud provider detection",
    subject_types=["ip"],
    description="Match IP against AWS, GCP, Cloudflare published ranges.",
    run=run,
))
