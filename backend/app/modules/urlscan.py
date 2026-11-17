"""urlscan.io — submit a URL and read the scan result.

With an API key it submits to urlscan.io/api/v1/scan and polls the result.
Without a key it falls back to the public search index.
"""
from __future__ import annotations
import asyncio
import httpx
from ..utils.ratelimit import gate
from ..utils.ssrf import assert_public, SSRFBlocked
from ..config import get_settings
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    s = get_settings()
    out = CollectionResult()
    v = (subject or "").strip()
    if not v:
        return out
    url = v if "://" in v else "https://" + v
    try:
        assert_public(url)
    except SSRFBlocked as e:
        out.findings.append(Finding("urlscan", "ssrf_blocked", {"url": url, "reason": str(e)}, 0.0))
        return out
    out.entities.append(Entity("url", url, {}, 0.9))

    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        if s.URLSCAN_API_KEY:
            await gate("urlscan")
            try:
                r = await c.post("https://urlscan.io/api/v1/scan/",
                                 headers={"API-Key": s.URLSCAN_API_KEY, "Content-Type": "application/json"},
                                 json={"url": url, "visibility": "unlisted"}, timeout=20)
                if r.status_code != 200:
                    out.findings.append(Finding("urlscan", "submit_error", {"status": r.status_code, "body": r.text[:400]}, 0.1))
                    return out
                j = r.json()
                scan_id = j.get("uuid")
                out.findings.append(Finding("urlscan", "submitted", {"uuid": scan_id, "api": j.get("api")}, 0.9))
                for _ in range(20):
                    await asyncio.sleep(3)
                    rr = await c.get(f"https://urlscan.io/api/v1/result/{scan_id}/", timeout=15)
                    if rr.status_code == 200:
                        res = rr.json()
                        page = res.get("page", {})
                        out.findings.append(Finding("urlscan", "result", {
                            "ip": page.get("ip"), "country": page.get("country"),
                            "domain": page.get("domain"), "server": page.get("server"),
                            "verdict": res.get("verdicts", {}).get("overall", {}),
                            "stats": res.get("stats", {}),
                            "result_url": f"https://urlscan.io/result/{scan_id}/",
                        }, 0.9))
                        ip = page.get("ip")
                        if ip:
                            out.entities.append(Entity("ip", ip, {"from": "urlscan"}, 0.85))
                            out.relationships.append(Relationship("url", url, "ip", ip, "served_from",
                                                                  "urlscan", 0.9))
                        return out
                out.findings.append(Finding("urlscan", "timeout", {"uuid": scan_id}, 0.3))
            except Exception as e:
                out.findings.append(Finding("urlscan", "error", {"error": str(e)}, 0.1))
            return out
        # keyless fallback — public search
        try:
            r = await c.get(f"https://urlscan.io/api/v1/search/?q=domain:{url.split('://',1)[-1].split('/',1)[0]}",
                            timeout=15)
            if r.status_code == 200:
                res = (r.json() or {}).get("results", [])[:10]
                out.findings.append(Finding("urlscan", "public_search",
                                            {"hits": len(res), "sample": res}, 0.7))
            else:
                out.findings.append(Finding("urlscan", "source_unavailable",
                                            {"reason": "no api key; public search returned " + str(r.status_code)}, 0.0))
        except Exception as e:
            out.findings.append(Finding("urlscan", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="urlscan",
    name="urlscan.io",
    subject_types=["url", "domain"],
    description="urlscan.io submission and result; falls back to public search.",
    run=run,
))
