"""Discord user-ID (snowflake) lookup.

Resolves a snowflake → public username, display name, avatar, banner,
account creation date (derivable mathematically from the ID itself),
and badges, via the keyless discordlookup.mesalytic.moe public API.
No auth, no bot token.
"""
from __future__ import annotations
import re
from datetime import datetime, timezone
import httpx
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


SNOWFLAKE_RE = re.compile(r"^\d{17,20}$")
DISCORD_EPOCH_MS = 1420070400000  # Discord's custom epoch — 2015-01-01 UTC


def snowflake_to_date(sid: str) -> dict:
    """Decode a snowflake into its component parts. Pure math, no network."""
    try:
        n = int(sid)
    except ValueError:
        return {}
    ts_ms = (n >> 22) + DISCORD_EPOCH_MS
    worker = (n >> 17) & 0x1F
    process = (n >> 12) & 0x1F
    increment = n & 0xFFF
    dt = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
    return {
        "created_at": dt.isoformat(),
        "created_at_unix_ms": ts_ms,
        "worker_id": worker,
        "process_id": process,
        "increment": increment,
    }


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    if not SNOWFLAKE_RE.match(v):
        out.findings.append(Finding("discord_id", "invalid_input",
                                    {"input": subject, "expected": "17–20 digit snowflake"}, 0.1))
        return out
    out.entities.append(Entity("discord", v, {"snowflake": v}, 0.95))

    decoded = snowflake_to_date(v)
    out.findings.append(Finding("discord_id", "snowflake_decode", decoded, 1.0))

    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            r = await c.get(f"https://discordlookup.mesalytic.moe/v1/user/{v}", timeout=15)
            if r.status_code == 200:
                j = r.json() or {}
                profile = {
                    "id": j.get("id"),
                    "username": j.get("username"),
                    "global_name": j.get("global_name"),
                    "discriminator": j.get("discriminator"),
                    "bot": j.get("bot"),
                    "public_flags": j.get("public_flags"),
                    "badges": j.get("badges"),
                    "accent_color": j.get("accent_color"),
                    "avatar": (j.get("avatar") or {}).get("link"),
                    "banner": (j.get("banner") or {}).get("link"),
                    "created_at": (j.get("created_at") or {}).get("iso") if isinstance(j.get("created_at"), dict) else j.get("created_at"),
                    "raw": j,
                }
                out.findings.append(Finding("discord_lookup", "user", profile, 0.9))
                uname = j.get("username") or j.get("global_name")
                if uname:
                    out.entities.append(Entity("username", uname[:64],
                                               {"platform": "discord", "snowflake": v},
                                               0.85))
                    out.relationships.append(Relationship("discord", v, "username", uname[:64],
                                                          "known_as", "discord_lookup", 0.9))
                avatar = profile.get("avatar")
                if avatar:
                    out.entities.append(Entity("url", avatar,
                                               {"kind": "discord_avatar", "snowflake": v}, 0.85))
            elif r.status_code == 404:
                out.findings.append(Finding("discord_lookup", "not_found", {"id": v}, 0.9))
            else:
                out.findings.append(Finding("discord_lookup", "http_error",
                                            {"status": r.status_code, "body": r.text[:200]}, 0.1))
        except Exception as e:
            out.findings.append(Finding("discord_lookup", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="discord_id",
    name="Discord user ID",
    subject_types=["discord"],
    description="Snowflake → public profile (keyless) + mathematically-derived creation date.",
    run=run,
))
