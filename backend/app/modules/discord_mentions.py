"""Discord handle + snowflake extractor over existing findings.

Scans every finding in the investigation for:
  - new-style handles          @alice  (unique-username era)
  - legacy tags                alice#1234
  - raw snowflakes             167348773909528576
  - discord.gg / discord.com invite links

Promotes each unique hit to the appropriate entity (`discord` for ids,
`username` for handles, `url` for invites) with a `mentions` relationship
from the finding's source entity when known.
"""
from __future__ import annotations
import json
import re
from sqlalchemy import select
from ..db import SessionLocal
from ..models import Finding
from .base import Module, Finding as F, Entity, Relationship, CollectionResult, RunContext, register


# Patterns designed to avoid false positives.
SNOWFLAKE_RE = re.compile(r"(?<!\d)(\d{17,20})(?!\d)")
LEGACY_TAG_RE = re.compile(r"\b([A-Za-z0-9_.\-]{2,32})#(\d{4})\b")
NEW_HANDLE_RE = re.compile(r"(?<![A-Za-z0-9._\-])@([a-z0-9._]{2,32})(?![A-Za-z0-9._\-])")
INVITE_RE = re.compile(r"(?:discord\.gg|discord\.com/invite)/([A-Za-z0-9\-]{2,32})", re.I)


def _looks_like_snowflake(s: str) -> bool:
    """Guard: only accept snowflakes whose derived creation date is plausible
    (Discord launched May 2015; cap at year 2100)."""
    try:
        n = int(s)
    except ValueError:
        return False
    ts_ms = (n >> 22) + 1420070400000
    return 1_420_070_400_000 <= ts_ms <= 4_102_444_800_000


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    async with SessionLocal() as db:
        finds = (await db.execute(
            select(Finding).where(Finding.investigation_id == ctx.investigation_id)
        )).scalars().all()

    snowflakes: dict[str, int] = {}
    legacy: dict[str, int] = {}
    new_handles: dict[str, int] = {}
    invites: dict[str, int] = {}

    for f in finds:
        blob = json.dumps(f.data or {}, default=str)
        for m in SNOWFLAKE_RE.findall(blob):
            if _looks_like_snowflake(m):
                snowflakes[m] = snowflakes.get(m, 0) + 1
        for name, disc in LEGACY_TAG_RE.findall(blob):
            tag = f"{name}#{disc}"
            legacy[tag] = legacy.get(tag, 0) + 1
        for h in NEW_HANDLE_RE.findall(blob):
            new_handles[h] = new_handles.get(h, 0) + 1
        for inv in INVITE_RE.findall(blob):
            invites[inv] = invites.get(inv, 0) + 1

    out.findings.append(F("discord_mentions", "summary", {
        "snowflakes": snowflakes, "legacy_tags": legacy,
        "new_handles": new_handles, "invites": invites,
        "total_distinct": len(snowflakes) + len(legacy) + len(new_handles) + len(invites),
    }, 0.9))

    for sid, cnt in snowflakes.items():
        out.entities.append(Entity("discord", sid, {"from": "mentions", "hits": cnt}, 0.7))
    for tag, cnt in legacy.items():
        out.entities.append(Entity("username", tag[:64],
                                   {"platform": "discord", "legacy": True, "hits": cnt}, 0.6))
    for h, cnt in new_handles.items():
        out.entities.append(Entity("username", h[:64],
                                   {"platform": "discord_candidate", "hits": cnt}, 0.45))
    for inv, cnt in invites.items():
        out.entities.append(Entity("url", f"https://discord.gg/{inv}",
                                   {"kind": "discord_invite", "code": inv, "hits": cnt}, 0.75))

    return out


register(Module(
    key="discord_mentions",
    name="Discord handles in findings",
    subject_types=["domain", "ip", "email", "username", "company", "url",
                   "document", "media", "phone", "btc", "eth", "discord"],
    description="Mines all collected findings for snowflakes, tags, @handles, and invite links.",
    run=run,
))
