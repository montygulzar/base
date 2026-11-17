"""WordPress enumeration — /wp-json/wp/v2/users and post feed.

For a WP install with REST API exposed, this unauth'd endpoint
historically returns every user with slug, name, and sometimes email.
Even on hardened installs the 'author' query may enum IDs.
"""
from __future__ import annotations
import httpx
from urllib.parse import urljoin
from ..utils.validators import normalise_domain
from ..utils.ssrf import assert_public, SSRFBlocked
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    base = v if "://" in v else "https://" + normalise_domain(v)
    try:
        assert_public(base)
    except SSRFBlocked as e:
        out.findings.append(Finding("wp_enum", "ssrf_blocked",
                                    {"url": base, "reason": str(e)}, 0.0))
        return out
    out.entities.append(Entity("url", base, {}, 0.9))
    async with httpx.AsyncClient(headers={"user-agent": "Mozilla/5.0 base-osint/0.1"},
                                 follow_redirects=True) as c:
        try:
            r = await c.get(urljoin(base + "/", "wp-json/wp/v2/users"),
                            params={"per_page": 50}, timeout=12)
            if r.status_code == 200:
                users = r.json() if r.text.strip() else []
                if isinstance(users, list):
                    out.findings.append(Finding("wp_enum", "users",
                                                {"count": len(users),
                                                 "users": [{"id": u.get("id"),
                                                             "slug": u.get("slug"),
                                                             "name": u.get("name")}
                                                            for u in users[:50]]},
                                                0.95 if users else 0.4))
                    for u in users[:50]:
                        slug = u.get("slug")
                        if slug:
                            out.entities.append(Entity("username", slug,
                                                       {"site": "wordpress", "url": base},
                                                       0.85))
                            out.relationships.append(Relationship("url", base, "username", slug,
                                                                  "has_user", "wp_enum", 0.9))
            else:
                out.findings.append(Finding("wp_enum", "users_locked",
                                            {"status": r.status_code}, 0.7))
            # posts feed as a secondary signal of WP install
            rr = await c.get(urljoin(base + "/", "wp-json/wp/v2/posts"),
                             params={"per_page": 5}, timeout=12)
            if rr.status_code == 200:
                out.findings.append(Finding("wp_enum", "posts_feed",
                                            {"status": rr.status_code,
                                             "post_count": len(rr.json() or [])}, 0.9))
        except Exception as e:
            out.findings.append(Finding("wp_enum", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="wp_enum",
    name="WordPress user enum",
    subject_types=["url", "domain"],
    description="wp-json/wp/v2/users for public WordPress user disclosure.",
    run=run,
))
