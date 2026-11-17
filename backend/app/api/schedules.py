"""Recurring investigation schedules."""
from __future__ import annotations
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user, require_role
from ..db import get_session
from ..models import Schedule, Investigation, AuditLog

router = APIRouter()


class ScheduleIn(BaseModel):
    investigation_id: str
    interval_seconds: int = 86400
    modules: list[str] | None = None


class ScheduleOut(BaseModel):
    id: str
    investigation_id: str
    interval_seconds: int
    modules: dict | list
    enabled: bool
    last_run_at: datetime | None
    next_run_at: datetime | None
    class Config: from_attributes = True


@router.post("", response_model=ScheduleOut)
async def create(data: ScheduleIn, u=Depends(require_role("admin", "analyst")),
                 db: AsyncSession = Depends(get_session)):
    if data.interval_seconds < 60:
        raise HTTPException(400, "interval must be >= 60s")
    inv = await db.get(Investigation, data.investigation_id)
    if not inv:
        raise HTTPException(404, "investigation not found")
    sch = Schedule(
        investigation_id=data.investigation_id,
        interval_seconds=data.interval_seconds,
        modules={"keys": data.modules or []},
        next_run_at=datetime.utcnow() + timedelta(seconds=data.interval_seconds),
    )
    db.add(sch)
    db.add(AuditLog(user_id=u.id, action="schedule.create",
                    target=data.investigation_id, detail={"interval": data.interval_seconds}))
    await db.commit(); await db.refresh(sch)
    return sch


@router.get("", response_model=list[ScheduleOut])
async def list_all(_: object = Depends(current_user), db: AsyncSession = Depends(get_session)):
    rows = (await db.execute(select(Schedule).order_by(Schedule.created_at.desc()))).scalars().all()
    return rows


@router.delete("/{sid}")
async def delete(sid: str, u=Depends(require_role("admin")), db: AsyncSession = Depends(get_session)):
    sch = await db.get(Schedule, sid)
    if not sch:
        raise HTTPException(404, "not found")
    await db.delete(sch)
    db.add(AuditLog(user_id=u.id, action="schedule.delete", target=sid))
    await db.commit()
    return {"deleted": sid}


@router.post("/{sid}/toggle")
async def toggle(sid: str, u=Depends(require_role("admin", "analyst")),
                 db: AsyncSession = Depends(get_session)):
    sch = await db.get(Schedule, sid)
    if not sch:
        raise HTTPException(404, "not found")
    sch.enabled = not sch.enabled
    db.add(AuditLog(user_id=u.id, action="schedule.toggle", target=sid,
                    detail={"enabled": sch.enabled}))
    await db.commit()
    return {"id": sid, "enabled": sch.enabled}
