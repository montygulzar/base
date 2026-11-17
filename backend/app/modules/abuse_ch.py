"""abuse.ch family — URLhaus, MalwareBazaar, FeodoTracker, SSLBL.

All free, keyless. Dispatches per subject type.
"""
from __future__ import annotations
import httpx
from ..utils.validators import is_ip, is_domain
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


async def _urlhaus_url(c: httpx.AsyncClient, url: str) -> dict:
    try:
        r = await c.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, timeout=15)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        return {"error": str(e)}
    return {}


async def _urlhaus_host(c: httpx.AsyncClient, host: str) -> dict:
    try:
        r = await c.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": host}, timeout=15)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        return {"error": str(e)}
    return {}


async def _malwarebazaar(c: httpx.AsyncClient, kind: str, value: str) -> dict:
    try:
        r = await c.post("https://mb-api.abuse.ch/api/v1/",
                         data={"query": kind, "hash": value} if kind.startswith("get_info") else
                              {"query": kind, "tag": value},
                         timeout=15)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        return {"error": str(e)}
    return {}


async def _feodo(c: httpx.AsyncClient, ip: str) -> dict:
    try:
        r = await c.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json", timeout=15)
        if r.status_code == 200:
            for row in r.json():
                if row.get("ip_address") == ip:
                    return {"hit": row}
            return {"hit": None}
    except Exception as e:
        return {"error": str(e)}
    return {}


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        if v.startswith("http"):
            out.entities.append(Entity("url", v, {}, 0.9))
            j = await _urlhaus_url(c, v)
            out.findings.append(Finding("urlhaus", "url", j, 0.85 if j else 0.2))
            return out
        if is_ip(v):
            out.entities.append(Entity("ip", v, {}, 0.9))
            u = await _urlhaus_host(c, v)
            f = await _feodo(c, v)
            out.findings.append(Finding("urlhaus", "host", u, 0.85 if u else 0.2))
            out.findings.append(Finding("feodotracker", "blocklist_check", f, 0.9 if f else 0.3))
            return out
        if is_domain(v):
            out.entities.append(Entity("domain", v, {}, 0.9))
            u = await _urlhaus_host(c, v)
            out.findings.append(Finding("urlhaus", "host", u, 0.85 if u else 0.2))
            return out
        if len(v) in (32, 40, 64):
            out.entities.append(Entity("hash", v.lower(), {}, 0.95))
            j = await _malwarebazaar(c, "get_info", v)
            out.findings.append(Finding("malwarebazaar", "sample_info", j, 0.9 if j else 0.2))
            data = (j.get("data") or []) if isinstance(j, dict) else []
            for row in data[:5]:
                tags = row.get("tags") or []
                for t in tags:
                    out.entities.append(Entity("username", f"malware_family:{t}", {"source": "malwarebazaar"}, 0.6))
                    out.relationships.append(Relationship("hash", v.lower(), "username", f"malware_family:{t}",
                                                          "tagged_as", "malwarebazaar", 0.85))
            return out
    out.findings.append(Finding("abuse_ch", "unrecognised_subject", {"input": v}, 0.1))
    return out


register(Module(
    key="abuse_ch",
    name="abuse.ch (URLhaus / MalwareBazaar / Feodo)",
    subject_types=["url", "domain", "ip", "document"],
    description="URLhaus + MalwareBazaar + FeodoTracker (keyless).",
    run=run,
))
