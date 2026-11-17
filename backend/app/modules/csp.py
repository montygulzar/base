"""Content Security Policy analyzer.

Fetches the subject URL, reads CSP header (or <meta http-equiv>), parses
directive-by-directive, and flags common weaknesses: 'unsafe-inline' on
script-src, wildcard (`*`) in script/connect/frame-src, missing
object-src/frame-ancestors/base-uri, http: allow, data: in script-src.
"""
from __future__ import annotations
import re
import httpx
from urllib.parse import urlparse
from ..utils.validators import normalise_domain
from ..utils.ssrf import assert_public, SSRFBlocked
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


WEAKNESSES = {
    "unsafe_inline_script": lambda d: "script-src" in d and "'unsafe-inline'" in d["script-src"],
    "wildcard_script": lambda d: "script-src" in d and "*" in d["script-src"],
    "wildcard_connect": lambda d: "connect-src" in d and "*" in d["connect-src"],
    "wildcard_frame": lambda d: "frame-src" in d and "*" in d["frame-src"],
    "missing_object_src": lambda d: "object-src" not in d,
    "missing_frame_ancestors": lambda d: "frame-ancestors" not in d,
    "missing_base_uri": lambda d: "base-uri" not in d,
    "http_allowed_script": lambda d: "script-src" in d and any("http:" in s for s in d["script-src"]),
    "data_in_script": lambda d: "script-src" in d and any(s.startswith("data:") for s in d["script-src"]),
}


def parse_csp(header: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in header.split(";"):
        part = part.strip()
        if not part:
            continue
        toks = part.split()
        if not toks:
            continue
        out[toks[0].lower()] = toks[1:]
    return out


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    url = v if "://" in v else "https://" + normalise_domain(v)
    try:
        assert_public(url)
    except SSRFBlocked as e:
        out.findings.append(Finding("csp", "ssrf_blocked",
                                    {"url": url, "reason": str(e)}, 0.0))
        return out
    async with httpx.AsyncClient(headers={"user-agent": "Mozilla/5.0 base-osint/0.1"},
                                 follow_redirects=True) as c:
        try:
            r = await c.get(url, timeout=15)
        except Exception as e:
            out.findings.append(Finding("csp", "error", {"error": str(e)}, 0.1))
            return out
    header = r.headers.get("content-security-policy", "") or r.headers.get("content-security-policy-report-only", "")
    if not header:
        # look for a meta tag
        m = re.search(r'<meta[^>]+http-equiv=["\']Content-Security-Policy["\'][^>]+content=["\']([^"\']+)["\']', r.text, re.I)
        if m:
            header = m.group(1)
    if not header:
        out.findings.append(Finding("csp", "missing", {"url": str(r.url)}, 0.9))
        return out
    parsed = parse_csp(header)
    weak = [name for name, pred in WEAKNESSES.items() if pred(parsed)]
    out.findings.append(Finding("csp", "analysis", {
        "url": str(r.url), "raw": header[:4000], "parsed": parsed,
        "weaknesses": weak, "verdict": "weak" if weak else "ok",
    }, 0.95))
    return out


register(Module(
    key="csp",
    name="CSP analyzer",
    subject_types=["url", "domain"],
    description="Parses Content-Security-Policy and flags common weaknesses.",
    run=run,
))
