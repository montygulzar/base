"""Fuzzy entity match — find entities across investigations whose value
is a close match to a needle. Pure-python Levenshtein-ratio (no deps).
"""
from __future__ import annotations
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..models import Entity

router = APIRouter()


def _ratio(a: str, b: str) -> float:
    a, b = a.lower(), b.lower()
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    la, lb = len(a), len(b)
    # one-row Levenshtein
    prev = list(range(lb + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * lb
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    d = prev[lb]
    return 1 - (d / max(la, lb))


@router.get("")
async def fuzzy(q: str, min_ratio: float = 0.8, limit: int = 50,
                type: str | None = None,
                _: object = Depends(current_user),
                db: AsyncSession = Depends(get_session)):
    needle = (q or "").strip()
    if not needle:
        return {"hits": []}
    query = select(Entity)
    if type:
        query = query.where(Entity.type == type)
    rows = (await db.execute(query)).scalars().all()
    scored = []
    for e in rows:
        s = _ratio(needle, e.value)
        if s >= min_ratio:
            scored.append({"id": e.id, "type": e.type, "value": e.value,
                            "investigation_id": e.investigation_id,
                            "confidence": e.confidence, "score": round(s, 3)})
    scored.sort(key=lambda r: r["score"], reverse=True)
    return {"query": needle, "hits": scored[:limit]}
