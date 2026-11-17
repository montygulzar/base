"""GitHub public-user intelligence.

Fetches profile, public repos, public events, gists. Works keyless at a
60/hr limit; if GITHUB_TOKEN is set, uses 5000/hr.
"""
from __future__ import annotations
import httpx
from ..config import get_settings
from ..utils.ratelimit import gate
from ..utils.validators import is_username
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    s = get_settings()
    out = CollectionResult()
    u = (subject or "").strip()
    if not is_username(u):
        out.findings.append(Finding("github", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("username", u, {}, 0.9))
    headers = {"user-agent": "base-osint/0.1", "accept": "application/vnd.github+json"}
    tok = getattr(s, "GITHUB_TOKEN", "") or ""
    if tok:
        headers["authorization"] = f"Bearer {tok}"
    async with httpx.AsyncClient(headers=headers) as c:
        await gate("github")
        try:
            r = await c.get(f"https://api.github.com/users/{u}", timeout=15)
            if r.status_code == 404:
                out.findings.append(Finding("github", "user", {"found": False}, 0.9))
                return out
            if r.status_code != 200:
                out.findings.append(Finding("github", "http_error",
                                            {"status": r.status_code, "body": r.text[:200]}, 0.1))
                return out
            profile = r.json()
            out.findings.append(Finding("github", "profile", {
                "login": profile.get("login"), "name": profile.get("name"),
                "bio": profile.get("bio"), "company": profile.get("company"),
                "email": profile.get("email"), "blog": profile.get("blog"),
                "location": profile.get("location"), "twitter": profile.get("twitter_username"),
                "public_repos": profile.get("public_repos"), "followers": profile.get("followers"),
                "created_at": profile.get("created_at"), "updated_at": profile.get("updated_at"),
            }, 0.9))
            if profile.get("email"):
                out.entities.append(Entity("email", profile["email"].lower(), {"from": "github"}, 0.85))
                out.relationships.append(Relationship("username", u, "email", profile["email"].lower(),
                                                      "self_identifies_as", "github_profile", 0.9))
            if profile.get("blog"):
                blog = profile["blog"]
                if blog.startswith("http"):
                    out.entities.append(Entity("url", blog, {"from": "github_blog"}, 0.8))
                    out.relationships.append(Relationship("username", u, "url", blog,
                                                          "self_linked", "github_profile", 0.85))

            rr = await c.get(f"https://api.github.com/users/{u}/repos?per_page=100&sort=updated",
                             timeout=20)
            if rr.status_code == 200:
                repos = [{
                    "name": x.get("full_name"), "lang": x.get("language"),
                    "stars": x.get("stargazers_count"), "forks": x.get("forks_count"),
                    "created": x.get("created_at"), "updated": x.get("pushed_at"),
                    "desc": x.get("description"), "url": x.get("html_url"),
                } for x in rr.json()]
                out.findings.append(Finding("github", "repos", {"count": len(repos), "repos": repos}, 0.9))

            re_ = await c.get(f"https://api.github.com/users/{u}/events/public?per_page=100", timeout=20)
            if re_.status_code == 200:
                events = [{"type": x.get("type"), "repo": (x.get("repo") or {}).get("name"),
                           "at": x.get("created_at")} for x in re_.json()]
                out.findings.append(Finding("github", "events", {"count": len(events), "events": events[:100]}, 0.85))

            rg = await c.get(f"https://api.github.com/users/{u}/gists?per_page=100", timeout=20)
            if rg.status_code == 200:
                gists = [{"id": x.get("id"), "desc": x.get("description"),
                          "files": list((x.get("files") or {}).keys()),
                          "created": x.get("created_at"), "url": x.get("html_url")} for x in rg.json()]
                out.findings.append(Finding("github", "gists", {"count": len(gists), "gists": gists}, 0.85))

        except Exception as e:
            out.findings.append(Finding("github", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="github_user",
    name="GitHub user",
    subject_types=["username"],
    description="Public profile, repos, events, gists.",
    run=run,
))
