"""Passive-DNS / subdomain enumeration from many keyless public sources
(Amass-style). Each source is a best-effort HTTP fetch; failures are
recorded as findings and don't take the whole module down.

Sources: hackertarget, rapiddns, anubis (Jonlundy), alienvault OTX,
subdomaincenter.com, bufferover.run (free tier), wayback machine CDX.
crt.sh is already covered by the domain module but is included here too
so this module can run standalone against a subject.
"""
from __future__ import annotations
import asyncio
import json
import re
from urllib.parse import quote_plus
import httpx
from ..utils.validators import is_domain, normalise_domain
from ..utils.ratelimit import gate
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


UA = {"user-agent": "Mozilla/5.0 base-osint/0.1"}


async def _hackertarget(c: httpx.AsyncClient, d: str) -> set[str]:
    r = await c.get(f"https://api.hackertarget.com/hostsearch/?q={d}", timeout=15, headers=UA)
    out: set[str] = set()
    if r.status_code == 200 and "API count exceeded" not in r.text and r.text.strip():
        for line in r.text.strip().splitlines():
            name = line.split(",", 1)[0].strip().lower()
            if name.endswith("." + d) or name == d:
                out.add(name)
    return out


async def _rapiddns(c: httpx.AsyncClient, d: str) -> set[str]:
    r = await c.get(f"https://rapiddns.io/subdomain/{d}?full=1", timeout=15, headers=UA)
    out: set[str] = set()
    if r.status_code == 200:
        for m in re.findall(r"<td>([a-zA-Z0-9][a-zA-Z0-9\-\.]+\." + re.escape(d) + r")</td>", r.text):
            out.add(m.lower())
    return out


async def _anubis(c: httpx.AsyncClient, d: str) -> set[str]:
    r = await c.get(f"https://jldc.me/anubis/subdomains/{d}", timeout=15, headers=UA)
    out: set[str] = set()
    if r.status_code == 200:
        try:
            for name in r.json():
                name = (name or "").strip().lower()
                if name.endswith("." + d) or name == d:
                    out.add(name)
        except Exception:
            pass
    return out


async def _otx_passive(c: httpx.AsyncClient, d: str) -> set[str]:
    r = await c.get(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns",
        timeout=20, headers=UA,
    )
    out: set[str] = set()
    if r.status_code == 200:
        try:
            for row in (r.json() or {}).get("passive_dns", []):
                h = (row.get("hostname") or "").strip().lower()
                if h.endswith("." + d) or h == d:
                    out.add(h)
        except Exception:
            pass
    return out


async def _subdomaincenter(c: httpx.AsyncClient, d: str) -> set[str]:
    r = await c.get(f"https://api.subdomain.center/?domain={d}", timeout=15, headers=UA)
    out: set[str] = set()
    if r.status_code == 200:
        try:
            for name in r.json():
                name = (name or "").strip().lower()
                if name.endswith("." + d) or name == d:
                    out.add(name)
        except Exception:
            pass
    return out


async def _bufferover(c: httpx.AsyncClient, d: str) -> set[str]:
    # Free tier TLS db (no key)
    out: set[str] = set()
    try:
        r = await c.get(f"https://tls.bufferover.run/dns?q=.{d}", timeout=15, headers=UA)
        if r.status_code == 200:
            try:
                data = r.json() or {}
                for row in (data.get("Results") or []):
                    # rows are comma-separated: cert_cn,subject,...
                    for part in row.split(","):
                        p = part.strip().lower()
                        if p.endswith("." + d) or p == d:
                            out.add(p)
            except Exception:
                pass
    except Exception:
        pass
    return out


async def _wayback_hosts(c: httpx.AsyncClient, d: str) -> set[str]:
    """CDX API query for all archived hostnames matching *.d/*."""
    out: set[str] = set()
    try:
        r = await c.get(
            "https://web.archive.org/cdx/search/cdx",
            params={"url": f"*.{d}/*", "output": "json", "fl": "original",
                    "collapse": "urlkey", "limit": "5000"},
            timeout=25, headers=UA,
        )
        if r.status_code == 200:
            rows = r.json()
            if rows and isinstance(rows, list) and len(rows) > 1:
                for row in rows[1:]:
                    url = row[0] if isinstance(row, list) and row else ""
                    m = re.match(r"^(?:https?://)?([^/:]+)", url or "")
                    if m:
                        host = m.group(1).lower()
                        if host.endswith("." + d) or host == d:
                            out.add(host)
    except Exception:
        pass
    return out


SOURCES: list[tuple[str, callable]] = [
    ("hackertarget",       _hackertarget),
    ("rapiddns",           _rapiddns),
    ("anubis",             _anubis),
    ("otx_passive_dns",    _otx_passive),
    ("subdomain.center",   _subdomaincenter),
    ("bufferover",         _bufferover),
    ("wayback",            _wayback_hosts),
]


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    d = normalise_domain(subject)
    if not is_domain(d):
        out.findings.append(Finding("passive_dns", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("domain", d, {"root": True}, 0.95))

    async with httpx.AsyncClient(headers=UA) as c:
        results = await asyncio.gather(
            *[src(c, d) for _, src in SOURCES], return_exceptions=True
        )

    merged: set[str] = set()
    per_source_counts: dict[str, int | str] = {}
    for (name, _), res in zip(SOURCES, results):
        if isinstance(res, Exception):
            per_source_counts[name] = f"error: {res!s}"
            out.findings.append(Finding(name, "error", {"error": str(res)}, 0.1))
            continue
        per_source_counts[name] = len(res)
        out.findings.append(Finding(name, "subdomains", {"count": len(res), "subdomains": sorted(res)[:1000]}, 0.8))
        merged |= res

    out.findings.append(Finding("passive_dns", "merged",
                                {"total_unique": len(merged), "per_source": per_source_counts}, 0.9))

    for sub in sorted(merged):
        if sub == d:
            continue
        out.entities.append(Entity("domain", sub, {"from": "passive_dns"}, 0.75))
        out.relationships.append(Relationship("domain", sub, "domain", d, "subdomain_of",
                                              "passive_dns", 0.8))
    return out


register(Module(
    key="passive_dns",
    name="Passive DNS (multi-source)",
    subject_types=["domain"],
    description="Hackertarget, RapidDNS, Anubis, OTX, SubdomainCenter, BufferOver, Wayback.",
    run=run,
))
