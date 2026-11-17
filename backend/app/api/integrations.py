from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..models import IntegrationStatus
from ..integrations import REGISTRY

router = APIRouter()


@router.get("")
async def list_integrations(db: AsyncSession = Depends(get_session), _: object = Depends(current_user)):
    rows = {r.name: r for r in (await db.execute(select(IntegrationStatus))).scalars().all()}
    out = []
    for name, meta in REGISTRY.items():
        row = rows.get(name)
        out.append({
            "name": name,
            "description": meta.get("description"),
            "scope": meta.get("scope"),
            "docs": meta.get("docs"),
            "configured": bool(meta.get("configured")),
            "last_ok_at": row.last_ok_at.isoformat() if row and row.last_ok_at else None,
            "last_error": row.last_error if row else "",
            "rate_limit_remaining": row.rate_limit_remaining if row else None,
        })
    return out
