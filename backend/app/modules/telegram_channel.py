"""Telegram public-channel preview via t.me/s/<handle>.

Parses the server-rendered preview page to confirm the channel exists
+ pull title / subscribers / description. No auth needed.
"""
from __future__ import annotations
import re
import httpx
from ..utils.validators import is_username
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


TITLE_RE = re.compile(r'<meta property="og:title" content="([^"]+)"')
DESC_RE = re.compile(r'<meta property="og:description" content="([^"]+)"')


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    u = (subject or "").strip().lstrip("@")
    if not is_username(u):
        out.findings.append(Finding("telegram", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("username", u, {"site": "telegram"}, 0.9))
    async with httpx.AsyncClient(headers={"user-agent": "Mozilla/5.0 base-osint/0.1"},
                                 follow_redirects=True) as c:
        try:
            r = await c.get(f"https://t.me/s/{u}", timeout=15)
            if r.status_code != 200:
                out.findings.append(Finding("telegram", "http_error",
                                            {"status": r.status_code}, 0.1))
                return out
            text = r.text
            title_m = TITLE_RE.search(text)
            desc_m = DESC_RE.search(text)
            # the s/ preview includes posts inline; if the handle is bad,
            # you get an empty title or a "If you have Telegram" banner
            exists = bool(title_m) and "If you have Telegram" not in (title_m.group(1) if title_m else "")
            out.findings.append(Finding("telegram", "preview",
                                        {"handle": u,
                                         "exists": exists,
                                         "title": title_m.group(1) if title_m else None,
                                         "description": desc_m.group(1) if desc_m else None,
                                         "url": f"https://t.me/{u}"},
                                        0.9 if exists else 0.5))
            if exists:
                out.entities.append(Entity("url", f"https://t.me/{u}",
                                           {"site": "telegram"}, 0.9))
        except Exception as e:
            out.findings.append(Finding("telegram", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="telegram_channel",
    name="Telegram channel preview",
    subject_types=["username"],
    description="t.me/s/<handle> preview — title, description, existence.",
    run=run,
))
