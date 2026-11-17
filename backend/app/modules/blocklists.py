"""Public IP blocklists — Tor exits, Spamhaus DROP, ET compromised,
Firehol level1. All keyless, cached in-process.
"""
from __future__ import annotations
import ipaddress
import httpx
from ..utils.validators import is_ip, is_private_ip
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


_FEEDS = {
    "tor_exits":       "https://check.torproject.org/torbulkexitlist",
    "spamhaus_drop":   "https://www.spamhaus.org/drop/drop.txt",
    "et_compromised":  "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "firehol_level1":  "https://iplists.firehol.org/files/firehol_level1.netset",
}
_cache: dict[str, tuple[list, list]] = {}  # name -> (plain_ips, networks)


def _parse(text: str) -> tuple[list[str], list]:
    ips: list[str] = []
    nets: list = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        tok = line.split()[0].rstrip(";")
        try:
            if "/" in tok:
                nets.append(ipaddress.ip_network(tok, strict=False))
            else:
                ipaddress.ip_address(tok)
                ips.append(tok)
        except ValueError:
            continue
    return ips, nets


async def _ensure(c: httpx.AsyncClient, name: str, url: str):
    if name in _cache:
        return
    try:
        r = await c.get(url, timeout=25)
        if r.status_code == 200:
            _cache[name] = _parse(r.text)
            return
    except Exception:
        pass
    _cache[name] = ([], [])


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    if not is_ip(v):
        out.findings.append(Finding("blocklists", "invalid_input", {"input": subject}, 0.1))
        return out
    if is_private_ip(v):
        out.findings.append(Finding("blocklists", "private_address", {"ip": v}, 1.0))
        return out
    out.entities.append(Entity("ip", v, {}, 0.95))
    ip_obj = ipaddress.ip_address(v)
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        for name, url in _FEEDS.items():
            await _ensure(c, name, url)
    hits = {}
    for name, (ips, nets) in _cache.items():
        if v in ips:
            hits[name] = "exact"
            continue
        for n in nets:
            if ip_obj in n:
                hits[name] = str(n)
                break
    out.findings.append(Finding("blocklists", "lookup",
                                {"ip": v, "feed_sizes": {k: len(_cache[k][0]) + len(_cache[k][1]) for k in _cache},
                                 "hits": hits},
                                0.95 if hits else 0.7))
    return out


register(Module(
    key="blocklists",
    name="Public blocklists",
    subject_types=["ip"],
    description="Tor / Spamhaus DROP / ET compromised / Firehol level1.",
    run=run,
))
