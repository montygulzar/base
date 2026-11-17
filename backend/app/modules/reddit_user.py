"""Reddit public-user intelligence.

Uses the public JSON endpoints (no auth required, rate-limited). Returns
about, recent posts, recent comments.
"""
from __future__ import annotations
import httpx
from ..utils.validators import is_username
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    u = (subject or "").strip().lstrip("u/").lstrip("@")
    if not is_username(u):
        out.findings.append(Finding("reddit", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("username", u, {"site": "reddit"}, 0.9))
    headers = {"user-agent": "base-osint/0.1 (research)"}
    async with httpx.AsyncClient(headers=headers) as c:
        try:
            about = await c.get(f"https://www.reddit.com/user/{u}/about.json", timeout=15)
            if about.status_code != 200:
                out.findings.append(Finding("reddit", "not_found", {"username": u,
                                                                     "status": about.status_code}, 0.9))
                return out
            a = (about.json() or {}).get("data") or {}
            out.findings.append(Finding("reddit", "about", {
                "name": a.get("name"), "id": a.get("id"),
                "karma": {"link": a.get("link_karma"), "comment": a.get("comment_karma"),
                          "total": a.get("total_karma")},
                "created_utc": a.get("created_utc"),
                "is_mod": a.get("is_mod"), "is_gold": a.get("is_gold"),
                "verified_email": a.get("has_verified_email"),
                "subreddit_desc": ((a.get("subreddit") or {}).get("public_description") or "")[:500],
            }, 0.9))
            subs = await c.get(f"https://www.reddit.com/user/{u}/submitted.json?limit=50", timeout=15)
            if subs.status_code == 200:
                posts = (subs.json() or {}).get("data", {}).get("children") or []
                out.findings.append(Finding("reddit", "submissions",
                                            {"count": len(posts),
                                             "sample": [{"sub": p["data"]["subreddit"],
                                                         "title": p["data"]["title"],
                                                         "created": p["data"]["created_utc"],
                                                         "url": "https://reddit.com" + p["data"]["permalink"]}
                                                        for p in posts[:20]]}, 0.9))
            com = await c.get(f"https://www.reddit.com/user/{u}/comments.json?limit=50", timeout=15)
            if com.status_code == 200:
                posts = (com.json() or {}).get("data", {}).get("children") or []
                out.findings.append(Finding("reddit", "comments",
                                            {"count": len(posts),
                                             "sample": [{"sub": p["data"]["subreddit"],
                                                         "body": (p["data"]["body"] or "")[:200],
                                                         "created": p["data"]["created_utc"]}
                                                        for p in posts[:20]]}, 0.9))
        except Exception as e:
            out.findings.append(Finding("reddit", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="reddit_user",
    name="Reddit user",
    subject_types=["username"],
    description="Public karma, submissions, comments.",
    run=run,
))
