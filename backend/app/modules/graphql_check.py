"""GraphQL endpoint discovery + introspection probe.

Attempts common endpoints (/graphql /api/graphql /v1/graphql /query).
For each, sends a tiny introspection query to see if the schema is
exposed (classic misconfig — never expose introspection in prod).
"""
from __future__ import annotations
import httpx
from urllib.parse import urljoin
from ..utils.ssrf import assert_public, SSRFBlocked
from ..utils.validators import normalise_domain
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query",
         "/graphql/v1", "/gql", "/api/gql"]
INTROSPECTION = "query{__schema{queryType{name} types{name kind}}}"


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    base = v if "://" in v else "https://" + normalise_domain(v)
    try:
        assert_public(base)
    except SSRFBlocked as e:
        out.findings.append(Finding("graphql_check", "ssrf_blocked",
                                    {"url": base, "reason": str(e)}, 0.0))
        return out
    results = []
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1",
                                          "content-type": "application/json"},
                                 follow_redirects=True) as c:
        for p in PATHS:
            url = urljoin(base + "/", p.lstrip("/"))
            try:
                r = await c.post(url, json={"query": INTROSPECTION}, timeout=10)
            except Exception as e:
                results.append({"url": url, "error": str(e)[:200]})
                continue
            info: dict = {"url": url, "status": r.status_code}
            try:
                body = r.json()
                if isinstance(body, dict) and "data" in body and "__schema" in str(body):
                    types = len(((body.get("data") or {}).get("__schema") or {}).get("types") or [])
                    info["introspection_open"] = True
                    info["type_count"] = types
                    out.entities.append(Entity("url", url,
                                               {"graphql": True, "introspection": True}, 0.9))
                elif isinstance(body, dict) and body.get("errors") and "Introspection" in str(body["errors"]):
                    info["introspection_open"] = False
                    info["disabled_message"] = str(body["errors"])[:200]
                    out.entities.append(Entity("url", url, {"graphql": True,
                                                              "introspection": False}, 0.9))
                else:
                    info["body_sample"] = str(body)[:300]
            except Exception:
                info["body_sample"] = r.text[:300]
            results.append(info)
    out.findings.append(Finding("graphql_check", "scan",
                                {"base": base, "results": results}, 0.9))
    return out


register(Module(
    key="graphql_check",
    name="GraphQL introspection discovery",
    subject_types=["url", "domain"],
    description="7-path GraphQL endpoint probe + introspection check.",
    run=run,
))
