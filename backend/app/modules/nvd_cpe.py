"""NVD CPE → CVE lookup.

Accepts a free-form product string (e.g. 'wordpress 5.8') and queries
NVD's cpes/2.0 then cves/2.0 endpoints. Keyless but rate-limited.
"""
from __future__ import annotations
import httpx
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    q = (subject or "").strip()
    if not q:
        out.findings.append(Finding("nvd_cpe", "invalid_input", {"input": subject}, 0.1))
        return out
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            r = await c.get("https://services.nvd.nist.gov/rest/json/cpes/2.0",
                            params={"keywordSearch": q, "resultsPerPage": 20},
                            timeout=25)
            if r.status_code != 200:
                out.findings.append(Finding("nvd_cpe", "http_error",
                                            {"status": r.status_code}, 0.1))
                return out
            products = (r.json() or {}).get("products") or []
            out.findings.append(Finding("nvd_cpe", "cpes",
                                        {"query": q, "count": len(products),
                                         "cpes": [{"cpe": (p.get("cpe") or {}).get("cpeName"),
                                                   "title": ((p.get("cpe") or {}).get("titles") or [{}])[0].get("title")}
                                                  for p in products[:20]]}, 0.9))
            seen_cves = set()
            for p in products[:5]:
                cpe = (p.get("cpe") or {}).get("cpeName")
                if not cpe:
                    continue
                rr = await c.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                                 params={"cpeName": cpe, "resultsPerPage": 25}, timeout=25)
                if rr.status_code == 200:
                    vulns = (rr.json() or {}).get("vulnerabilities") or []
                    for v in vulns:
                        cve = ((v.get("cve") or {}).get("id") or "").upper()
                        if cve and cve not in seen_cves:
                            seen_cves.add(cve)
                            out.entities.append(Entity("cve", cve, {"source": "nvd_cpe", "cpe": cpe}, 0.9))
                            out.relationships.append(Relationship("cve", cve, "cve", cpe,
                                                                  "affects", "nvd", 0.85))
            out.findings.append(Finding("nvd_cpe", "cves",
                                        {"query": q, "distinct_cves": len(seen_cves),
                                         "cves": sorted(seen_cves)[:100]},
                                        0.9 if seen_cves else 0.4))
        except Exception as e:
            out.findings.append(Finding("nvd_cpe", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="nvd_cpe",
    name="NVD CPE lookup",
    subject_types=["document", "company", "domain"],
    description="Free-form product → CPE → CVE (NVD, keyless).",
    run=run,
))
