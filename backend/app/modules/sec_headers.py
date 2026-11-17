"""Security-header grader (securityheaders.com-style, local scoring).

Fetches the URL, checks for 10 headers, assigns per-header points,
returns a letter grade A..F with reasoning.
"""
from __future__ import annotations
import httpx
from ..utils.validators import normalise_domain
from ..utils.ssrf import assert_public, SSRFBlocked
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


CHECKS = [
    # (header, weight, predicate)
    ("strict-transport-security", 20, lambda v: v and "max-age" in v.lower() and int(
        next((p.split("=", 1)[1] for p in v.lower().split(";") if p.strip().startswith("max-age=")), "0").strip() or "0") >= 15768000),
    ("content-security-policy",   20, lambda v: bool(v)),
    ("x-content-type-options",    10, lambda v: (v or "").strip().lower() == "nosniff"),
    ("x-frame-options",           10, lambda v: bool(v)),
    ("referrer-policy",            8, lambda v: bool(v)),
    ("permissions-policy",         8, lambda v: bool(v)),
    ("cross-origin-opener-policy", 8, lambda v: bool(v)),
    ("cross-origin-embedder-policy", 6, lambda v: bool(v)),
    ("cross-origin-resource-policy", 5, lambda v: bool(v)),
    ("x-permitted-cross-domain-policies", 5, lambda v: bool(v)),
]


def _grade(pct: float) -> str:
    if pct >= 90: return "A"
    if pct >= 80: return "B"
    if pct >= 65: return "C"
    if pct >= 50: return "D"
    if pct >= 30: return "E"
    return "F"


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    url = v if "://" in v else "https://" + normalise_domain(v)
    try:
        assert_public(url)
    except SSRFBlocked as e:
        out.findings.append(Finding("sec_headers", "ssrf_blocked",
                                    {"url": url, "reason": str(e)}, 0.0))
        return out
    out.entities.append(Entity("url", url, {}, 0.9))
    async with httpx.AsyncClient(headers={"user-agent": "Mozilla/5.0 base-osint/0.1"},
                                 follow_redirects=True) as c:
        try:
            r = await c.get(url, timeout=12)
        except Exception as e:
            out.findings.append(Finding("sec_headers", "error", {"error": str(e)}, 0.1))
            return out
    present_headers = {k.lower(): v for k, v in r.headers.items()}
    details = []
    score = 0
    total = 0
    for h, w, pred in CHECKS:
        total += w
        val = present_headers.get(h)
        try:
            ok = pred(val)
        except Exception:
            ok = False
        if ok:
            score += w
        details.append({"header": h, "weight": w, "value": val, "ok": ok})
    pct = (score * 100) // total if total else 0
    out.findings.append(Finding("sec_headers", "grade",
                                {"url": str(r.url), "grade": _grade(pct),
                                 "score": pct, "max": total,
                                 "details": details}, 0.95))
    return out


register(Module(
    key="sec_headers",
    name="Security header grader",
    subject_types=["url", "domain"],
    description="Weighted A..F score across 10 security-related response headers.",
    run=run,
))
