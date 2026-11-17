"""Ahmia — tor hidden service search, keyless.

Looks up both clearnet (.onion addresses listed) and darknet. Does NOT
actually connect to .onion addresses (would need a SOCKS5/tor proxy);
emits the found .onion URLs as entities for the analyst.
"""
from __future__ import annotations
import re
import httpx
from .base import Module, Finding, Entity, CollectionResult, RunContext, register

ONION_RE = re.compile(r"\b([a-z2-7]{16}\.onion|[a-z2-7]{56}\.onion)\b")


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    q = (subject or "").strip()
    if not q:
        return out
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            r = await c.get("https://ahmia.fi/search/", params={"q": q}, timeout=25)
            if r.status_code != 200:
                out.findings.append(Finding("ahmia", "http_error",
                                            {"status": r.status_code}, 0.1))
                return out
            onions = sorted(set(ONION_RE.findall(r.text)))
            out.findings.append(Finding("ahmia", "search",
                                        {"query": q, "onions_found": len(onions),
                                         "onions": onions[:100]},
                                        0.9 if onions else 0.4))
            for o in onions[:100]:
                out.entities.append(Entity("url", f"http://{o}",
                                           {"from": "ahmia", "query": q, "onion": True}, 0.6))
        except Exception as e:
            out.findings.append(Finding("ahmia", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="ahmia",
    name="Ahmia (tor search)",
    subject_types=["domain", "company", "username", "email"],
    description="ahmia.fi full-text tor search (keyless).",
    run=run,
))
