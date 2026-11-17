"""CORS policy analyzer.

Fetches the URL with an Origin header and inspects the ACAO/ACAC
response. Flags wildcards combined with credentials, reflected-origin
misconfigs, and missing policy entirely.
"""
from __future__ import annotations
import httpx
from ..utils.validators import normalise_domain
from ..utils.ssrf import assert_public, SSRFBlocked
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


PROBE_ORIGIN = "https://attacker.example"


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    url = v if "://" in v else "https://" + normalise_domain(v)
    try:
        assert_public(url)
    except SSRFBlocked as e:
        out.findings.append(Finding("cors", "ssrf_blocked",
                                    {"url": url, "reason": str(e)}, 0.0))
        return out
    out.entities.append(Entity("url", url, {}, 0.9))
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"},
                                 follow_redirects=True) as c:
        try:
            r = await c.get(url, headers={"origin": PROBE_ORIGIN}, timeout=12)
        except Exception as e:
            out.findings.append(Finding("cors", "error", {"error": str(e)}, 0.1))
            return out
    acao = r.headers.get("access-control-allow-origin", "")
    acac = (r.headers.get("access-control-allow-credentials", "") or "").lower() == "true"
    acam = r.headers.get("access-control-allow-methods", "")
    verdict = "ok"
    reasons: list[str] = []
    if not acao:
        verdict = "no_cors"
    elif acao == "*":
        if acac:
            verdict = "insecure"; reasons.append("wildcard_with_credentials")
    elif acao == PROBE_ORIGIN:
        verdict = "suspicious"; reasons.append("reflected_origin")
        if acac:
            reasons.append("reflected_with_credentials"); verdict = "insecure"
    elif acao.endswith("null"):
        reasons.append("null_origin_allowed")
        if acac:
            verdict = "insecure"
    out.findings.append(Finding("cors", "analysis",
                                {"url": str(r.url),
                                 "acao": acao, "acac": acac, "acam": acam,
                                 "verdict": verdict, "reasons": reasons,
                                 "probe_origin": PROBE_ORIGIN}, 0.95))
    return out


register(Module(
    key="cors",
    name="CORS analyzer",
    subject_types=["url", "domain"],
    description="Probes Access-Control-Allow-Origin with a bogus origin.",
    run=run,
))
