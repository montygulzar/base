"""URL unshortener — follow redirects up to N hops and report the chain."""
from __future__ import annotations
import httpx
from ..utils.ssrf import assert_public, SSRFBlocked
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    if not v.startswith("http"):
        out.findings.append(Finding("url_unshorten", "invalid_input", {"input": subject}, 0.1))
        return out
    try:
        assert_public(v)
    except SSRFBlocked as e:
        out.findings.append(Finding("url_unshorten", "ssrf_blocked",
                                    {"url": v, "reason": str(e)}, 0.0))
        return out
    out.entities.append(Entity("url", v, {}, 0.9))

    chain: list[dict] = []
    current = v
    async with httpx.AsyncClient(headers={"user-agent": "Mozilla/5.0 base-osint/0.1"}) as c:
        for _ in range(10):
            try:
                r = await c.head(current, timeout=10, follow_redirects=False)
            except Exception:
                try:
                    r = await c.get(current, timeout=10, follow_redirects=False)
                except Exception as e:
                    chain.append({"url": current, "error": str(e)[:200]})
                    break
            chain.append({"url": current, "status": r.status_code,
                          "location": r.headers.get("location")})
            if 300 <= r.status_code < 400 and r.headers.get("location"):
                loc = r.headers["location"]
                if not loc.startswith(("http://", "https://")):
                    from urllib.parse import urljoin
                    loc = urljoin(current, loc)
                try:
                    assert_public(loc)
                except SSRFBlocked:
                    chain.append({"url": loc, "error": "ssrf_blocked"})
                    break
                current = loc
            else:
                break
    final = chain[-1]["url"] if chain else v
    out.findings.append(Finding("url_unshorten", "chain",
                                {"start": v, "final": final,
                                 "hops": len(chain), "chain": chain}, 0.95))
    if final != v and final.startswith("http"):
        out.entities.append(Entity("url", final, {"from": "unshorten"}, 0.85))
        out.relationships.append(Relationship("url", v, "url", final,
                                              "redirects_to", "url_unshorten", 0.95))
    return out


register(Module(
    key="url_unshorten",
    name="URL unshortener",
    subject_types=["url"],
    description="Follow redirects, record every hop; SSRF-guarded per step.",
    run=run,
))
