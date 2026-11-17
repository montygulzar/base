"""Hacker News (news.ycombinator.com) mentions via the Algolia search API."""
from __future__ import annotations
import httpx
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    q = (subject or "").strip()
    if not q:
        return out
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            r = await c.get("https://hn.algolia.com/api/v1/search",
                            params={"query": q, "hitsPerPage": 30}, timeout=15)
            if r.status_code == 200:
                j = r.json()
                hits = j.get("hits") or []
                out.findings.append(Finding("hackernews", "search",
                                            {"query": q, "count": len(hits),
                                             "hits": [{"title": h.get("title"),
                                                       "author": h.get("author"),
                                                       "url": h.get("url"),
                                                       "points": h.get("points"),
                                                       "comments": h.get("num_comments"),
                                                       "created": h.get("created_at"),
                                                       "object_id": h.get("objectID"),
                                                       "story_url": f"https://news.ycombinator.com/item?id={h.get('objectID')}"}
                                                      for h in hits[:30]]},
                                            0.9 if hits else 0.4))
                for h in hits[:30]:
                    if h.get("author"):
                        out.entities.append(Entity("username", h["author"],
                                                   {"site": "hackernews"}, 0.6))
            else:
                out.findings.append(Finding("hackernews", "http_error",
                                            {"status": r.status_code}, 0.1))
        except Exception as e:
            out.findings.append(Finding("hackernews", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="hackernews",
    name="Hacker News mentions",
    subject_types=["company", "domain", "username"],
    description="Algolia HN search for mentions / discussions / users.",
    run=run,
))
