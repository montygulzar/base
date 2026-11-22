"""Bulk IOC ingest.

Accepts a newline/comma/space-separated list of indicators and classifies
each into an entity type via validators. No modules are triggered — the
caller can then hit /run or /expand to enrich.

Supported detection: ipv4/ipv6, domain, url, email, sha256 (64 hex),
sha1 (40 hex), md5 (32 hex), CVE-YYYY-NNNNN.
"""
from __future__ import annotations
import re
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import require_role
from ..db import get_session
from ..models import Investigation, Entity, AuditLog
from ..utils.validators import is_ip, is_domain, is_email

router = APIRouter()
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
HEX_RE = re.compile(r"^[a-fA-F0-9]+$")
SNOWFLAKE_RE = re.compile(r"^\d{17,20}$")
DISCORD_INVITE_RE = re.compile(r"^(?:https?://)?(?:discord\.gg|discord\.com/invite)/[A-Za-z0-9\-]{2,32}$", re.I)


def _is_plausible_snowflake(s: str) -> bool:
    try:
        n = int(s)
    except ValueError:
        return False
    ts_ms = (n >> 22) + 1420070400000  # Discord epoch
    return 1_420_070_400_000 <= ts_ms <= 4_102_444_800_000


class IngestIn(BaseModel):
    text: str


def classify(tok: str) -> tuple[str, str] | None:
    t = tok.strip().strip(",;")
    if not t:
        return None
    if CVE_RE.match(t):
        return "cve", t.upper()
    if DISCORD_INVITE_RE.match(t):
        return "url", t
    if SNOWFLAKE_RE.match(t) and _is_plausible_snowflake(t):
        return "discord", t
    if t.startswith(("http://", "https://")):
        return "url", t
    if is_email(t):
        return "email", t.lower()
    if is_ip(t):
        return "ip", t
    if is_domain(t):
        return "domain", t.lower()
    if HEX_RE.match(t):
        if len(t) == 64: return "hash", t.lower()
        if len(t) == 40: return "hash", t.lower()
        if len(t) == 32: return "hash", t.lower()
    return None


@router.post("/{inv_id}")
async def ingest(inv_id: str, data: IngestIn, u=Depends(require_role("admin", "analyst")),
                 db: AsyncSession = Depends(get_session)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "not found")
    tokens = re.split(r"[\s,;]+", data.text or "")
    added = 0
    skipped: list[str] = []
    for tok in tokens:
        c = classify(tok)
        if not c:
            if tok: skipped.append(tok)
            continue
        kind, value = c
        q = select(Entity).where(Entity.investigation_id == inv_id,
                                 Entity.type == kind, Entity.value == value)
        if (await db.execute(q)).scalar_one_or_none():
            continue
        db.add(Entity(investigation_id=inv_id, type=kind, value=value,
                      attributes={"source": "ingest"}, confidence=0.7))
        added += 1
    db.add(AuditLog(user_id=u.id, action="ioc.ingest", target=inv_id,
                    detail={"added": added, "skipped_count": len(skipped)}))
    await db.commit()
    return {"added": added, "skipped": skipped[:50], "total_input": len(tokens)}
