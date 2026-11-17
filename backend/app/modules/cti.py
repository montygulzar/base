"""Cyber threat intelligence — IOC reputation and CVE lookup.

Dispatches on subject type: ip|domain|url|hash -> reputation feeds;
'cve' values -> NVD.
"""
from __future__ import annotations
import httpx
from ..config import get_settings
from ..utils.validators import is_ip, is_domain
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


async def _otx(client, s, kind: str, value: str) -> dict:
    headers = {"X-OTX-API-KEY": s.OTX_API_KEY} if s.OTX_API_KEY else {}
    try:
        r = await client.get(f"https://otx.alienvault.com/api/v1/indicators/{kind}/{value}/general",
                             headers=headers, timeout=15)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        return {"error": str(e)}
    return {}


async def _threatfox(client, value: str) -> dict:
    try:
        r = await client.post("https://threatfox-api.abuse.ch/api/v1/",
                              json={"query": "search_ioc", "search_term": value}, timeout=15)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        return {"error": str(e)}
    return {}


async def _nvd(client, cve: str) -> dict:
    try:
        r = await client.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}", timeout=20)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        return {"error": str(e)}
    return {}


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    s = get_settings()
    out = CollectionResult()
    v = (subject or "").strip()
    if not v:
        return out

    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as client:
        if v.upper().startswith("CVE-"):
            out.entities.append(Entity("cve", v.upper(), {}, 0.95))
            j = await _nvd(client, v.upper())
            out.findings.append(Finding("nvd", "cve", j, 0.9 if j else 0.2))
            return out

        if is_ip(v):
            kind = "IPv6" if ":" in v else "IPv4"
            out.entities.append(Entity("ip", v, {}, 0.9))
            otx, tf = await _otx(client, s, kind, v), await _threatfox(client, v)
            out.findings.append(Finding("otx", "ip", otx, 0.85 if otx else 0.2))
            out.findings.append(Finding("threatfox", "ioc", tf, 0.85 if tf else 0.2))
            return out

        if is_domain(v):
            out.entities.append(Entity("domain", v, {}, 0.9))
            otx, tf = await _otx(client, s, "domain", v), await _threatfox(client, v)
            out.findings.append(Finding("otx", "domain", otx, 0.85 if otx else 0.2))
            out.findings.append(Finding("threatfox", "ioc", tf, 0.85 if tf else 0.2))
            return out

        if v.startswith("http"):
            out.entities.append(Entity("url", v, {}, 0.9))
            otx = await _otx(client, s, "url", v)
            out.findings.append(Finding("otx", "url", otx, 0.85 if otx else 0.2))
            return out

        # treat as file hash
        if len(v) in (32, 40, 64):
            out.entities.append(Entity("hash", v.lower(), {}, 0.9))
            otx = await _otx(client, s, "file", v)
            out.findings.append(Finding("otx", "file", otx, 0.85 if otx else 0.2))
            return out

    out.findings.append(Finding("cti", "unrecognised_subject", {"input": v}, 0.1))
    return out


register(Module(
    key="cti",
    name="Threat intelligence",
    subject_types=["ip", "domain", "url", "document"],
    description="OTX, ThreatFox, NVD. CVE / IOC lookups.",
    run=run,
))
