"""Mastodon profile lookup via webfinger + instance API."""
from __future__ import annotations
import httpx
from ..utils.validators import is_username
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip().lstrip("@")
    if "@" not in v:
        v = f"{v}@mastodon.social"
    if not is_username(v.split("@", 1)[0]):
        out.findings.append(Finding("mastodon", "invalid_input", {"input": subject}, 0.1))
        return out
    user, instance = v.split("@", 1)
    out.entities.append(Entity("username", v, {"site": "mastodon", "instance": instance}, 0.9))
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            wf = await c.get(f"https://{instance}/.well-known/webfinger",
                             params={"resource": f"acct:{v}"}, timeout=15,
                             follow_redirects=True)
            if wf.status_code != 200:
                out.findings.append(Finding("mastodon", "not_found", {"input": v}, 0.9))
                return out
            links = (wf.json() or {}).get("links") or []
            profile_url = next((l["href"] for l in links if l.get("rel") == "http://webfinger.net/rel/profile-page"), "")
            activity_url = next((l["href"] for l in links if l.get("rel") == "self"), "")
            # account lookup on instance API
            lookup = await c.get(f"https://{instance}/api/v1/accounts/lookup",
                                 params={"acct": v}, timeout=15)
            prof = lookup.json() if lookup.status_code == 200 else {}
            out.findings.append(Finding("mastodon", "profile", {
                "handle": v, "instance": instance, "profile_url": profile_url,
                "activity_url": activity_url,
                "display_name": prof.get("display_name"),
                "followers": prof.get("followers_count"),
                "following": prof.get("following_count"),
                "statuses": prof.get("statuses_count"),
                "created_at": prof.get("created_at"),
                "note": (prof.get("note") or "")[:500],
            }, 0.9))
            if profile_url:
                out.entities.append(Entity("url", profile_url, {"site": "mastodon"}, 0.85))
        except Exception as e:
            out.findings.append(Finding("mastodon", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="mastodon",
    name="Mastodon profile",
    subject_types=["username"],
    description="Mastodon webfinger + instance API lookup.",
    run=run,
))
