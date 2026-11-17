"""Gravatar — an email address's public profile and avatar."""
from __future__ import annotations
import hashlib
import httpx
from ..utils.validators import is_email
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip().lower()
    if not is_email(v):
        out.findings.append(Finding("gravatar", "invalid_input", {"input": subject}, 0.1))
        return out
    h = hashlib.md5(v.encode()).hexdigest()
    sha = hashlib.sha256(v.encode()).hexdigest()
    out.entities.append(Entity("email", v, {}, 0.95))
    out.findings.append(Finding("gravatar", "hashes",
                                {"md5": h, "sha256": sha}, 1.0))
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            r = await c.get(f"https://en.gravatar.com/{h}.json", timeout=15)
            if r.status_code == 200:
                j = r.json()
                entry = (j.get("entry") or [])
                out.findings.append(Finding("gravatar", "profile",
                                            {"entries": entry}, 0.9))
                for e in entry:
                    name = e.get("preferredUsername") or e.get("displayName") or ""
                    if name:
                        out.entities.append(Entity("username", name[:64], {"source": "gravatar"}, 0.75))
                        out.relationships.append(Relationship("email", v, "username", name[:64],
                                                              "self_identifies_as", "gravatar", 0.85))
                    for acc in (e.get("accounts") or []):
                        url = acc.get("url")
                        if url:
                            out.entities.append(Entity("url", url, {"site": acc.get("shortname")}, 0.75))
                            out.relationships.append(Relationship("email", v, "url", url,
                                                                  "self_linked", "gravatar", 0.85))
            elif r.status_code == 404:
                out.findings.append(Finding("gravatar", "no_profile", {"md5": h}, 0.9))
            else:
                out.findings.append(Finding("gravatar", "http_error", {"status": r.status_code}, 0.1))
        except Exception as e:
            out.findings.append(Finding("gravatar", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="gravatar",
    name="Gravatar",
    subject_types=["email"],
    description="Public Gravatar profile and account links by email md5.",
    run=run,
))
