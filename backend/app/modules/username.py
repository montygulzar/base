"""Username / public profile discovery (Sherlock-style).

Checks a curated catalogue of public platforms. Every hit is emitted as a
candidate match — matching username never implies same person.
"""
from __future__ import annotations
import asyncio
import httpx
from ..utils.validators import is_username
from ..config import get_settings
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register

# site -> (url template, detection: status|contains, extra)
SITES: dict[str, dict] = {
    "github":       {"url": "https://github.com/{u}",           "method": "status", "ok": 200, "bad": 404},
    "gitlab":       {"url": "https://gitlab.com/{u}",           "method": "status", "ok": 200, "bad": 404},
    "twitter":      {"url": "https://twitter.com/{u}",          "method": "status", "ok": 200, "bad": 404},
    "x":            {"url": "https://x.com/{u}",                "method": "status", "ok": 200, "bad": 404},
    "reddit":       {"url": "https://www.reddit.com/user/{u}",  "method": "status", "ok": 200, "bad": 404},
    "medium":       {"url": "https://medium.com/@{u}",          "method": "status", "ok": 200, "bad": 404},
    "dev.to":       {"url": "https://dev.to/{u}",               "method": "status", "ok": 200, "bad": 404},
    "stackoverflow":{"url": "https://stackoverflow.com/users/{u}","method":"status","ok": 200, "bad": 404},
    "keybase":      {"url": "https://keybase.io/{u}",           "method": "status", "ok": 200, "bad": 404},
    "hackernews":   {"url": "https://news.ycombinator.com/user?id={u}", "method": "contains", "needle": "created:", "ok": 200},
    "tiktok":       {"url": "https://www.tiktok.com/@{u}",      "method": "status", "ok": 200, "bad": 404},
    "youtube":      {"url": "https://www.youtube.com/@{u}",     "method": "status", "ok": 200, "bad": 404},
    "twitch":       {"url": "https://www.twitch.tv/{u}",        "method": "status", "ok": 200, "bad": 404},
    "instagram":    {"url": "https://www.instagram.com/{u}/",   "method": "status", "ok": 200, "bad": 404},
    "patreon":      {"url": "https://www.patreon.com/{u}",      "method": "status", "ok": 200, "bad": 404},
    "steam":        {"url": "https://steamcommunity.com/id/{u}","method": "contains", "needle": "profile_header", "ok": 200},
    "pinterest":    {"url": "https://www.pinterest.com/{u}/",   "method": "status", "ok": 200, "bad": 404},
    "spotify":      {"url": "https://open.spotify.com/user/{u}","method": "status", "ok": 200, "bad": 404},
    "soundcloud":   {"url": "https://soundcloud.com/{u}",       "method": "status", "ok": 200, "bad": 404},
    "vimeo":        {"url": "https://vimeo.com/{u}",            "method": "status", "ok": 200, "bad": 404},
    "flickr":       {"url": "https://www.flickr.com/people/{u}","method": "status", "ok": 200, "bad": 404},
    "bitbucket":    {"url": "https://bitbucket.org/{u}/",       "method": "status", "ok": 200, "bad": 404},
    "replit":       {"url": "https://replit.com/@{u}",          "method": "status", "ok": 200, "bad": 404},
    "codepen":      {"url": "https://codepen.io/{u}",           "method": "status", "ok": 200, "bad": 404},
    "duolingo":     {"url": "https://www.duolingo.com/profile/{u}", "method": "status", "ok": 200, "bad": 404},
    "lichess":      {"url": "https://lichess.org/@/{u}",        "method": "status", "ok": 200, "bad": 404},
    "chess.com":    {"url": "https://www.chess.com/member/{u}", "method": "status", "ok": 200, "bad": 404},
    "goodreads":    {"url": "https://www.goodreads.com/{u}",    "method": "status", "ok": 200, "bad": 404},
    "producthunt":  {"url": "https://www.producthunt.com/@{u}", "method": "status", "ok": 200, "bad": 404},
    "ycombinator":  {"url": "https://news.ycombinator.com/user?id={u}", "method": "contains", "needle": "karma", "ok": 200},
    "about.me":     {"url": "https://about.me/{u}",             "method": "status", "ok": 200, "bad": 404},
    "gravatar":     {"url": "https://en.gravatar.com/{u}",      "method": "status", "ok": 200, "bad": 404},
    "last.fm":      {"url": "https://www.last.fm/user/{u}",     "method": "status", "ok": 200, "bad": 404},
    "ok.ru":        {"url": "https://ok.ru/{u}",                "method": "status", "ok": 200, "bad": 404},
    "vk":           {"url": "https://vk.com/{u}",               "method": "contains", "needle": "profile", "ok": 200},
    "wikipedia":    {"url": "https://en.wikipedia.org/wiki/User:{u}", "method": "status", "ok": 200, "bad": 404},
    "wordpress":    {"url": "https://{u}.wordpress.com/",       "method": "status", "ok": 200, "bad": 404},
    "blogger":      {"url": "https://{u}.blogspot.com/",        "method": "status", "ok": 200, "bad": 404},
    "tumblr":       {"url": "https://{u}.tumblr.com/",          "method": "status", "ok": 200, "bad": 404},
    "quora":        {"url": "https://www.quora.com/profile/{u}","method": "status", "ok": 200, "bad": 404},
    "ebay":         {"url": "https://www.ebay.com/usr/{u}",     "method": "status", "ok": 200, "bad": 404},
    "roblox":       {"url": "https://www.roblox.com/user.aspx?username={u}", "method": "status", "ok": 200, "bad": 404},
    "xbox":         {"url": "https://xboxgamertag.com/search/{u}","method": "contains","needle":"Gamerscore","ok":200},
    "mastodon.social": {"url": "https://mastodon.social/@{u}",  "method": "status", "ok": 200, "bad": 404},
    "threads":      {"url": "https://www.threads.net/@{u}",     "method": "status", "ok": 200, "bad": 404},
    "bluesky":      {"url": "https://bsky.app/profile/{u}.bsky.social", "method": "status", "ok": 200, "bad": 404},
    "npm":          {"url": "https://www.npmjs.com/~{u}",       "method": "status", "ok": 200, "bad": 404},
    "pypi":         {"url": "https://pypi.org/user/{u}/",       "method": "status", "ok": 200, "bad": 404},
    "rubygems":     {"url": "https://rubygems.org/profiles/{u}","method": "status", "ok": 200, "bad": 404},
    "crates.io":    {"url": "https://crates.io/users/{u}",      "method": "status", "ok": 200, "bad": 404},
    "docker":       {"url": "https://hub.docker.com/u/{u}",     "method": "status", "ok": 200, "bad": 404},
    "etsy":         {"url": "https://www.etsy.com/shop/{u}",    "method": "status", "ok": 200, "bad": 404},
    "angellist":    {"url": "https://wellfound.com/u/{u}",      "method": "status", "ok": 200, "bad": 404},
    "linktree":     {"url": "https://linktr.ee/{u}",            "method": "status", "ok": 200, "bad": 404},
}


async def _check(client: httpx.AsyncClient, site: str, cfg: dict, u: str) -> dict:
    url = cfg["url"].format(u=u)
    try:
        r = await client.get(url, timeout=10, follow_redirects=True)
        if cfg["method"] == "status":
            present = r.status_code == cfg["ok"]
        else:
            present = r.status_code == cfg["ok"] and cfg["needle"].lower() in r.text.lower()
        return {"site": site, "url": url, "status": r.status_code, "present": present}
    except Exception as e:
        return {"site": site, "url": url, "error": str(e), "present": False}


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    s = get_settings()
    out = CollectionResult()
    u = (subject or "").strip()
    if not is_username(u):
        out.findings.append(Finding("username", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("username", u, {}, 0.95))

    sem = asyncio.Semaphore(16)

    async def guarded(client, name, cfg):
        async with sem:
            return await _check(client, name, cfg, u)

    async with httpx.AsyncClient(headers={"user-agent": "Mozilla/5.0 base-osint/0.1"}) as client:
        results = await asyncio.gather(*(guarded(client, name, cfg) for name, cfg in SITES.items()))

    present = [r for r in results if r.get("present")]
    out.findings.append(Finding("sherlock", "profile_matches",
                                {"found": present, "checked": len(SITES), "hits": len(present)},
                                0.65))  # candidate — not identity

    for r in present:
        out.entities.append(Entity("url", r["url"], {"site": r["site"], "username": u}, 0.65))
        out.relationships.append(Relationship("username", u, "url", r["url"], "candidate_profile",
                                              f"platform:{r['site']}", 0.6, {"note": "username match ≠ same person"}))
    return out


register(Module(
    key="username",
    name="Public profile search",
    subject_types=["username"],
    description="Checks ~50 public platforms for a username (candidate matches).",
    run=run,
))
