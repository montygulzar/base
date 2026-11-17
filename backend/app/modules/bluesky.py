"""Bluesky (AT Protocol) public profile lookup."""
from __future__ import annotations
import httpx
from ..utils.validators import is_username
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    u = (subject or "").strip().lstrip("@")
    if not is_username(u):
        out.findings.append(Finding("bluesky", "invalid_input", {"input": subject}, 0.1))
        return out
    handle = u if "." in u else f"{u}.bsky.social"
    out.entities.append(Entity("username", u, {}, 0.9))
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            r = await c.get("https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile",
                            params={"actor": handle}, timeout=15)
            if r.status_code == 200:
                j = r.json()
                out.findings.append(Finding("bluesky", "profile", {
                    "handle": j.get("handle"), "did": j.get("did"),
                    "display_name": j.get("displayName"), "description": j.get("description"),
                    "followers": j.get("followersCount"),
                    "follows": j.get("followsCount"), "posts": j.get("postsCount"),
                    "created_at": j.get("createdAt"),
                }, 0.9))
                if j.get("did"):
                    out.entities.append(Entity("url", f"https://bsky.app/profile/{j.get('handle')}",
                                               {"site": "bluesky"}, 0.85))
            elif r.status_code == 400:
                out.findings.append(Finding("bluesky", "not_found", {"handle": handle}, 0.9))
            else:
                out.findings.append(Finding("bluesky", "http_error",
                                            {"status": r.status_code}, 0.1))
        except Exception as e:
            out.findings.append(Finding("bluesky", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="bluesky",
    name="Bluesky profile",
    subject_types=["username"],
    description="AT-protocol public profile for a handle.",
    run=run,
))
