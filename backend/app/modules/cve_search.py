"""CVE keyword search via NIST NVD (keyless, rate-limited)."""
from __future__ import annotations
import httpx
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    q = (subject or "").strip()
    if not q:
        out.findings.append(Finding("cve_search", "invalid_input", {"input": subject}, 0.1))
        return out
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            r = await c.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                            params={"keywordSearch": q, "resultsPerPage": 50},
                            timeout=25)
            if r.status_code != 200:
                out.findings.append(Finding("nvd", "http_error",
                                            {"status": r.status_code}, 0.1))
                return out
            vulns = (r.json() or {}).get("vulnerabilities") or []
            cves = []
            for v in vulns:
                c_obj = v.get("cve") or {}
                cves.append({"id": c_obj.get("id"),
                             "published": c_obj.get("published"),
                             "lastModified": c_obj.get("lastModified"),
                             "descriptions": [d.get("value") for d in (c_obj.get("descriptions") or [])
                                              if d.get("lang") == "en"][:1],
                             "metrics": c_obj.get("metrics", {}).keys() and list(c_obj["metrics"].keys()) or []})
            out.findings.append(Finding("nvd", "keyword_search",
                                        {"query": q, "count": len(cves),
                                         "cves": cves[:50]},
                                        0.9 if cves else 0.4))
            for c_rec in cves[:50]:
                if c_rec.get("id"):
                    out.entities.append(Entity("cve", c_rec["id"], {"source": "nvd_keyword"}, 0.85))
        except Exception as e:
            out.findings.append(Finding("nvd", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="cve_search",
    name="CVE keyword search (NVD)",
    subject_types=["company", "domain", "document"],
    description="NIST NVD keyword search for CVE entries.",
    run=run,
))
