"""GitHub code dork — search public code for mentions of a domain.

Uses /search/code which requires authentication for content, but
/search/repositories works keyless. We prefer code with a token; fall
back to repository name/description search if no token is set.
"""
from __future__ import annotations
import httpx
from ..config import get_settings
from ..utils.validators import is_domain, normalise_domain
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


DORKS = [
    "{d}",
    "\"{d}\" password",
    "\"{d}\" api_key",
    "\"{d}\" secret",
    "\"{d}\" env",
    "\"{d}\" credentials",
    "site:github.com \"{d}\"",
]


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    s = get_settings()
    out = CollectionResult()
    d = normalise_domain(subject)
    if not is_domain(d):
        out.findings.append(Finding("github_dorks", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("domain", d, {}, 0.9))
    headers = {"user-agent": "base-osint/0.1", "accept": "application/vnd.github+json"}
    token = getattr(s, "GITHUB_TOKEN", "") or ""
    if token:
        headers["authorization"] = f"Bearer {token}"
    async with httpx.AsyncClient(headers=headers) as c:
        if token:
            for dork in DORKS[:5]:
                q = dork.format(d=d)
                try:
                    r = await c.get("https://api.github.com/search/code",
                                    params={"q": q, "per_page": 10}, timeout=20)
                    if r.status_code == 200:
                        items = (r.json() or {}).get("items") or []
                        out.findings.append(Finding("github_code", "dork",
                                                    {"q": q, "count": len(items),
                                                     "hits": [{"name": x.get("name"),
                                                               "repo": (x.get("repository") or {}).get("full_name"),
                                                               "url": x.get("html_url")}
                                                              for x in items]},
                                                    0.85 if items else 0.3))
                        for x in items[:10]:
                            if x.get("html_url"):
                                out.entities.append(Entity("url", x["html_url"],
                                                           {"site": "github", "q": q}, 0.65))
                                out.relationships.append(Relationship("domain", d, "url", x["html_url"],
                                                                      "mentioned_in_code", "github_dorks", 0.6))
                    elif r.status_code == 403:
                        out.findings.append(Finding("github_code", "rate_limited",
                                                    {"q": q}, 0.3))
                        break
                except Exception as e:
                    out.findings.append(Finding("github_code", "error", {"q": q, "error": str(e)}, 0.1))
                    break
        else:
            try:
                r = await c.get("https://api.github.com/search/repositories",
                                params={"q": d, "per_page": 20, "sort": "stars"}, timeout=20)
                if r.status_code == 200:
                    items = (r.json() or {}).get("items") or []
                    out.findings.append(Finding("github_repos", "search",
                                                {"domain": d, "count": len(items),
                                                 "hits": [{"full_name": x.get("full_name"),
                                                           "stars": x.get("stargazers_count"),
                                                           "desc": x.get("description"),
                                                           "url": x.get("html_url")}
                                                          for x in items]},
                                                0.85 if items else 0.3))
                    for x in items[:20]:
                        if x.get("html_url"):
                            out.entities.append(Entity("url", x["html_url"],
                                                       {"site": "github_repo"}, 0.6))
            except Exception as e:
                out.findings.append(Finding("github_repos", "error", {"error": str(e)}, 0.1))
            out.findings.append(Finding("github_code", "source_unavailable",
                                        {"reason": "code search needs GITHUB_TOKEN"}, 0.0))
    return out


register(Module(
    key="github_dorks",
    name="GitHub code / repo dorks",
    subject_types=["domain", "company"],
    description="Search GitHub code (with token) or repos (keyless) for a domain.",
    run=run,
))
