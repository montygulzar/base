"""Shodan InternetDB — free, no-key per-IP summary (ports, hostnames,
CPEs, tags, vulnerabilities).
"""
from __future__ import annotations
import httpx
from ..utils.validators import is_ip, is_private_ip
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    ip = (subject or "").strip()
    if not is_ip(ip):
        out.findings.append(Finding("internetdb", "invalid_input", {"input": subject}, 0.1))
        return out
    if is_private_ip(ip):
        out.findings.append(Finding("internetdb", "private_address", {"ip": ip}, 1.0))
        return out
    out.entities.append(Entity("ip", ip, {}, 0.9))
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            r = await c.get(f"https://internetdb.shodan.io/{ip}", timeout=15)
            if r.status_code == 200:
                j = r.json()
                out.findings.append(Finding("internetdb", "host", j, 0.9))
                for h in j.get("hostnames", []):
                    if "." in h:
                        out.entities.append(Entity("domain", h.lower(), {"from": "internetdb"}, 0.8))
                        out.relationships.append(Relationship("domain", h.lower(), "ip", ip,
                                                              "resolves_to", "internetdb", 0.85))
                for v in j.get("vulns", []):
                    cve = (v or "").upper()
                    if cve.startswith("CVE-"):
                        out.entities.append(Entity("cve", cve, {"source": "internetdb"}, 0.85))
                        out.relationships.append(Relationship("ip", ip, "cve", cve,
                                                              "exposed_to", "internetdb", 0.85))
            elif r.status_code == 404:
                out.findings.append(Finding("internetdb", "no_data", {"ip": ip}, 0.5))
            else:
                out.findings.append(Finding("internetdb", "http_error", {"status": r.status_code}, 0.1))
        except Exception as e:
            out.findings.append(Finding("internetdb", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="internetdb",
    name="Shodan InternetDB",
    subject_types=["ip"],
    description="Free per-IP Shodan summary: ports, hostnames, CPEs, vulns.",
    run=run,
))
