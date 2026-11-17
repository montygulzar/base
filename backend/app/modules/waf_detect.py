"""WAF / CDN detector via response headers + cookie fingerprints.

Sends one GET with a bogus request-id header; scans the response
headers, status, and set-cookie for ~25 known-WAF/CDN signatures.
"""
from __future__ import annotations
import httpx
from ..utils.validators import normalise_domain
from ..utils.ssrf import assert_public, SSRFBlocked
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


SIGS: dict[str, dict] = {
    "cloudflare":    {"headers": ["cf-ray", "cf-cache-status", "cf-request-id"], "cookies": ["__cfduid", "__cf_bm"]},
    "akamai":        {"headers": ["x-akamai-request-id", "akamai-grn"], "cookies": ["akamai-bm"]},
    "fastly":        {"headers": ["x-fastly-request-id"], "cookies": []},
    "aws_waf":       {"headers": [], "cookies": ["aws-waf-token", "awswafsessiontoken"]},
    "cloudfront":    {"headers": ["x-amz-cf-id", "x-amz-cf-pop"], "cookies": []},
    "sucuri":        {"headers": ["x-sucuri-id", "x-sucuri-cache"], "cookies": []},
    "imperva":       {"headers": ["x-iinfo"], "cookies": ["incap_ses", "visid_incap"]},
    "f5":            {"headers": ["x-waf-event-info"], "cookies": ["ts", "bigipserver"]},
    "wordfence":     {"headers": [], "cookies": ["wordfence_verifiedhuman"]},
    "barracuda":     {"headers": ["x-cnection"], "cookies": ["barra_counter_session"]},
    "citrix":        {"headers": [], "cookies": ["ns_af"]},
    "stackpath":     {"headers": ["server: stackpath"], "cookies": []},
    "google_cdn":    {"headers": ["via: 1.1 google"], "cookies": []},
    "azure_front_door":{"headers": ["x-azure-ref"], "cookies": []},
    "ddos_guard":    {"headers": ["server: ddos-guard"], "cookies": []},
}


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    url = v if "://" in v else "https://" + normalise_domain(v)
    try:
        assert_public(url)
    except SSRFBlocked as e:
        out.findings.append(Finding("waf", "ssrf_blocked",
                                    {"url": url, "reason": str(e)}, 0.0))
        return out
    out.entities.append(Entity("url", url, {}, 0.9))
    async with httpx.AsyncClient(headers={"user-agent": "Mozilla/5.0 base-osint/0.1",
                                          "x-base-probe": "1"},
                                 follow_redirects=True) as c:
        try:
            r = await c.get(url, timeout=12)
        except Exception as e:
            out.findings.append(Finding("waf", "error", {"error": str(e)}, 0.1))
            return out
    headers = {k.lower(): v for k, v in r.headers.items()}
    cookies = ";".join(v for k, v in r.headers.items() if k.lower() == "set-cookie").lower()
    detections = []
    for name, sig in SIGS.items():
        for h in sig["headers"]:
            if ":" in h:
                k, _, val = h.partition(": ")
                if k.lower() in headers and val.lower() in headers[k.lower()].lower():
                    detections.append({"product": name, "match": h}); break
            elif h.lower() in headers:
                detections.append({"product": name, "match": h}); break
        for cookie in sig["cookies"]:
            if cookie.lower() in cookies:
                detections.append({"product": name, "match": "cookie:" + cookie}); break
    out.findings.append(Finding("waf", "detect",
                                {"url": str(r.url),
                                 "detections": detections,
                                 "server": headers.get("server"),
                                 "status": r.status_code},
                                0.95 if detections else 0.5))
    return out


register(Module(
    key="waf_detect",
    name="WAF / CDN detector",
    subject_types=["url", "domain"],
    description="Header + cookie fingerprinting for 15 common WAFs/CDNs.",
    run=run,
))
