"""/api/version — live platform info (module count, integration count,
test timestamp, DB row counts).
"""
from __future__ import annotations
from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..modules import REGISTRY
from ..integrations import REGISTRY as INTEG_REGISTRY
from ..models import Investigation, Entity, Finding, Job, User

router = APIRouter()


@router.get("")
async def version(_: object = Depends(current_user),
                  db: AsyncSession = Depends(get_session)):
    counts = {
        "users": (await db.execute(select(func.count(User.id)))).scalar() or 0,
        "investigations": (await db.execute(select(func.count(Investigation.id)))).scalar() or 0,
        "entities": (await db.execute(select(func.count(Entity.id)))).scalar() or 0,
        "findings": (await db.execute(select(func.count(Finding.id)))).scalar() or 0,
        "jobs": (await db.execute(select(func.count(Job.id)))).scalar() or 0,
    }
    return {
        "name": "base",
        "version": "0.1.0",
        "modules": len(REGISTRY),
        "integrations": len(INTEG_REGISTRY),
        "module_names": sorted(REGISTRY.keys()),
        "counts": counts,
    }
