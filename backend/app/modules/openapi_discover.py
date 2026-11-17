"""OpenAPI / Swagger document discovery.

Attempts common paths (/openapi.json, /swagger.json, /api-docs,
/v1/openapi, /v2/openapi, /swagger/v1/swagger.json). Reports found
documents + their info.title + info.version + path count.
"""
from __future__ import annotations
import httpx
from urllib.parse import urljoin
from ..utils.validators import normalise_domain
from ..utils.ssrf import assert_public, SSRFBlocked
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


CANDIDATES = ["/openapi.json", "/swagger.json", "/api-docs",
              "/v1/openapi", "/v2/openapi",
              "/swagger/v1/swagger.json", "/api/openapi.json",
              "/api/swagger.json", "/docs/openapi.json"]


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    base = v if "://" in v else "https://" + normalise_domain(v)
    try:
        assert_public(base)
    except SSRFBlocked as e:
        out.findings.append(Finding("openapi", "ssrf_blocked",
                                    {"url": base, "reason": str(e)}, 0.0))
        return out
    hits = []
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"},
                                 follow_redirects=True) as c:
        for p in CANDIDATES:
            url = urljoin(base + "/", p.lstrip("/"))
            try:
                r = await c.get(url, timeout=10)
            except Exception:
                continue
            if r.status_code != 200 or len(r.text) < 50:
                continue
            try:
                j = r.json()
            except Exception:
                continue
            if "openapi" in j or "swagger" in j or "info" in j:
                info = j.get("info") or {}
                hits.append({
                    "url": url, "title": info.get("title"),
                    "version": info.get("version"),
                    "paths": len(j.get("paths") or {}),
                    "openapi_version": j.get("openapi") or j.get("swagger"),
                })
                out.entities.append(Entity("url", url, {"openapi": True,
                                                         "title": info.get("title")}, 0.85))
    out.findings.append(Finding("openapi", "scan",
                                {"base": base, "hits": hits,
                                 "found": len(hits)},
                                0.9 if hits else 0.4))
    return out


register(Module(
    key="openapi",
    name="OpenAPI / Swagger discovery",
    subject_types=["url", "domain"],
    description="9-path probe for exposed OpenAPI / Swagger documents.",
    run=run,
))
