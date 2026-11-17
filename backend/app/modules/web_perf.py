"""Basic web performance probe — TTFB, total time, bytes, hop count."""
from __future__ import annotations
import time
import httpx
from ..utils.validators import normalise_domain
from ..utils.ssrf import assert_public, SSRFBlocked
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    url = v if "://" in v else "https://" + normalise_domain(v)
    try:
        assert_public(url)
    except SSRFBlocked as e:
        out.findings.append(Finding("web_perf", "ssrf_blocked",
                                    {"url": url, "reason": str(e)}, 0.0))
        return out
    out.entities.append(Entity("url", url, {}, 0.9))
    async with httpx.AsyncClient(headers={"user-agent": "Mozilla/5.0 base-osint/0.1"},
                                 follow_redirects=True) as c:
        start = time.monotonic()
        first_byte_at = None
        try:
            async with c.stream("GET", url, timeout=20) as r:
                async for chunk in r.aiter_bytes(1024):
                    if first_byte_at is None:
                        first_byte_at = time.monotonic()
                    break  # we only care about TTFB here
                total = time.monotonic() - start
                try:
                    content = await r.aread()
                except Exception:
                    content = b""
            total_time = time.monotonic() - start
            out.findings.append(Finding("web_perf", "probe", {
                "url": str(r.url),
                "final_status": r.status_code,
                "ttfb_ms": round(((first_byte_at or start) - start) * 1000, 2),
                "total_ms": round(total_time * 1000, 2),
                "bytes": len(content),
                "server": r.headers.get("server"),
                "content_type": r.headers.get("content-type"),
                "redirected_from": v if str(r.url) != v else None,
            }, 0.95))
        except Exception as e:
            out.findings.append(Finding("web_perf", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="web_perf",
    name="Web perf probe",
    subject_types=["url", "domain"],
    description="TTFB + total time + bytes for a single HTTP GET.",
    run=run,
))
