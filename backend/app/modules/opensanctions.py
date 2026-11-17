"""OpenSanctions — free, keyless public sanctions / PEP / watchlist search.

Query by a company / person name. Returns matched entities from
sanctions lists, PEP registries, warrant databases.
"""
from __future__ import annotations
import httpx
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    q = (subject or "").strip()
    if not q:
        return out
    out.entities.append(Entity("org", q, {}, 0.85))
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            r = await c.get("https://api.opensanctions.org/search/default",
                            params={"q": q, "limit": 25}, timeout=20)
            if r.status_code != 200:
                out.findings.append(Finding("opensanctions", "http_error",
                                            {"status": r.status_code, "body": r.text[:200]}, 0.1))
                return out
            j = r.json() or {}
            results = j.get("results") or []
            out.findings.append(Finding("opensanctions", "search",
                                        {"total": j.get("total") or {}, "count": len(results),
                                         "results": [{"id": x.get("id"),
                                                      "schema": x.get("schema"),
                                                      "caption": x.get("caption"),
                                                      "datasets": x.get("datasets"),
                                                      "topics": (x.get("properties") or {}).get("topics"),
                                                      "countries": (x.get("properties") or {}).get("country"),
                                                      "score": x.get("score")}
                                                     for x in results]},
                                        0.9 if results else 0.5))
            for x in results[:25]:
                caption = x.get("caption") or ""
                if caption:
                    schema = x.get("schema") or "entity"
                    entity_type = "username" if schema in ("Person", "LegalEntity") else "org"
                    out.entities.append(Entity(entity_type, caption[:80],
                                               {"opensanctions_id": x.get("id"),
                                                "datasets": x.get("datasets"),
                                                "schema": schema}, 0.75))
                    out.relationships.append(Relationship("org", q, entity_type, caption[:80],
                                                          "sanctions_match", "opensanctions", 0.7,
                                                          {"score": x.get("score")}))
        except Exception as e:
            out.findings.append(Finding("opensanctions", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="opensanctions",
    name="OpenSanctions",
    subject_types=["company", "username"],
    description="Sanctions / PEP / watchlist search (keyless).",
    run=run,
))
