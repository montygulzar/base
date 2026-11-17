"""OSV — open source vulnerability database (keyless).

Queries by package name or raw CVE id and returns known advisories.
"""
from __future__ import annotations
import httpx
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    if not v:
        return out

    is_cve = v.upper().startswith("CVE-")
    body: dict = {}
    if is_cve:
        body = {"commit": None, "version": None, "package": None,
                "vulnerability": {"id": v.upper()}}
    elif ":" in v:
        # ecosystem:package[:version], e.g. PyPI:requests:2.0.0
        parts = v.split(":")
        if len(parts) >= 2:
            body = {"package": {"ecosystem": parts[0], "name": parts[1]}}
            if len(parts) > 2 and parts[2]:
                body["version"] = parts[2]
    else:
        body = {"package": {"name": v}}

    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            r = await c.post("https://api.osv.dev/v1/query", json=body, timeout=20)
            if r.status_code == 200:
                vulns = (r.json() or {}).get("vulns") or []
                out.findings.append(Finding("osv", "query",
                                            {"input": v, "count": len(vulns),
                                             "vulns": [{"id": x.get("id"),
                                                        "summary": x.get("summary"),
                                                        "aliases": x.get("aliases"),
                                                        "modified": x.get("modified"),
                                                        "severity": x.get("severity")}
                                                       for x in vulns[:50]]},
                                            0.9 if vulns else 0.5))
                for x in vulns[:50]:
                    for a in (x.get("aliases") or []) + [x.get("id") or ""]:
                        if a and a.upper().startswith("CVE-"):
                            out.entities.append(Entity("cve", a.upper(), {"source": "osv"}, 0.85))
            else:
                out.findings.append(Finding("osv", "http_error",
                                            {"status": r.status_code, "body": r.text[:200]}, 0.1))
        except Exception as e:
            out.findings.append(Finding("osv", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="osv",
    name="OSV",
    subject_types=["document", "url", "domain", "ip"],
    description="Open Source Vulnerability database query (keyless).",
    run=run,
))
