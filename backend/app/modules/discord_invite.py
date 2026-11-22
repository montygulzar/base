"""Discord invite / server lookup.

Uses Discord's own public /api/v10/invites/{code} endpoint (no auth
required) to resolve an invite code to its server metadata, inviter
public info, and approximate member count.

Accepts either a bare code or a full discord.gg / discord.com invite URL.
"""
from __future__ import annotations
import re
import httpx
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


INVITE_RE = re.compile(r"(?:discord\.gg/|discord\.com/invite/)?([A-Za-z0-9\-]{2,32})")


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    m = INVITE_RE.search(v)
    if not m:
        out.findings.append(Finding("discord_invite", "invalid_input", {"input": subject}, 0.1))
        return out
    code = m.group(1)
    out.entities.append(Entity("url", f"https://discord.gg/{code}",
                               {"kind": "discord_invite", "code": code}, 0.9))
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            r = await c.get(f"https://discord.com/api/v10/invites/{code}",
                            params={"with_counts": "true", "with_expiration": "true"},
                            timeout=15)
            if r.status_code == 200:
                j = r.json() or {}
                guild = j.get("guild") or {}
                inviter = j.get("inviter") or {}
                chan = j.get("channel") or {}
                summary = {
                    "code": code,
                    "server_id": guild.get("id"),
                    "server_name": guild.get("name"),
                    "server_description": guild.get("description"),
                    "server_features": guild.get("features"),
                    "server_verification": guild.get("verification_level"),
                    "server_nsfw_level": guild.get("nsfw_level"),
                    "member_total": j.get("approximate_member_count"),
                    "member_online": j.get("approximate_presence_count"),
                    "channel": {"id": chan.get("id"), "name": chan.get("name"), "type": chan.get("type")},
                    "inviter": {
                        "id": inviter.get("id"),
                        "username": inviter.get("username"),
                        "global_name": inviter.get("global_name"),
                        "public_flags": inviter.get("public_flags"),
                    } if inviter else None,
                    "expires_at": j.get("expires_at"),
                    "icon": guild.get("icon"),
                    "splash": guild.get("splash"),
                    "vanity_url_code": guild.get("vanity_url_code"),
                }
                out.findings.append(Finding("discord_invite", "resolved", summary, 0.95))
                if guild.get("id"):
                    out.entities.append(Entity("org", (guild.get("name") or "")[:80],
                                               {"platform": "discord", "server_id": guild.get("id"),
                                                "member_total": j.get("approximate_member_count")},
                                               0.85))
                if inviter.get("id"):
                    out.entities.append(Entity("discord", inviter["id"],
                                               {"role": "inviter", "server_id": guild.get("id")}, 0.85))
                    out.relationships.append(Relationship("discord", inviter["id"],
                                                          "org", (guild.get("name") or "")[:80],
                                                          "invited_to", "discord_invite", 0.9))
            elif r.status_code == 404:
                out.findings.append(Finding("discord_invite", "expired_or_invalid", {"code": code}, 0.9))
            else:
                out.findings.append(Finding("discord_invite", "http_error",
                                            {"status": r.status_code, "body": r.text[:200]}, 0.1))
        except Exception as e:
            out.findings.append(Finding("discord_invite", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="discord_invite",
    name="Discord invite / server",
    subject_types=["url", "discord"],
    description="Discord's own public invite endpoint — server name, counts, features, inviter, channel.",
    run=run,
))
