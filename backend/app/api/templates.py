"""Investigation templates.

A template bundles: a name, a description, a module plan per subject
type, and optional default subject types. Instantiating a template
creates a new investigation populated with any supplied subjects.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user, require_role
from ..db import get_session
from ..models import InvestigationTemplate, Investigation, Subject, AuditLog
from ..queue import enqueue_run


router = APIRouter()


class TmplIn(BaseModel):
    name: str
    description: str = ""
    modules: dict[str, list[str]] = {}  # subject_type -> [module_key, ...]


class InstantiateIn(BaseModel):
    name: str
    subjects: list[dict] = []  # [{type, value, note?}, ...]
    run: bool = True


@router.post("", response_model=dict)
async def create(data: TmplIn, _=Depends(require_role("admin", "analyst")),
                 db: AsyncSession = Depends(get_session)):
    existing = (await db.execute(select(InvestigationTemplate).where(
        InvestigationTemplate.name == data.name))).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "name exists")
    t = InvestigationTemplate(name=data.name, description=data.description,
                              modules={"plan": data.modules}, subject_types={"keys": list(data.modules)})
    db.add(t); await db.commit(); await db.refresh(t)
    return {"id": t.id, "name": t.name}


@router.get("")
async def list_all(_=Depends(current_user), db: AsyncSession = Depends(get_session)):
    rows = (await db.execute(select(InvestigationTemplate))).scalars().all()
    return [{"id": r.id, "name": r.name, "description": r.description,
             "modules": (r.modules or {}).get("plan", {}),
             "created_at": r.created_at.isoformat()} for r in rows]


@router.post("/{tid}/instantiate", response_model=dict)
async def instantiate(tid: str, data: InstantiateIn,
                      u=Depends(require_role("admin", "analyst")),
                      db: AsyncSession = Depends(get_session)):
    t = await db.get(InvestigationTemplate, tid)
    if not t:
        raise HTTPException(404, "not found")
    inv = Investigation(name=data.name, description=t.description, owner_id=u.id)
    db.add(inv); await db.flush()
    for s in data.subjects:
        if "type" in s and "value" in s:
            db.add(Subject(investigation_id=inv.id, type=s["type"], value=s["value"],
                           note=s.get("note", "")))
    db.add(AuditLog(user_id=u.id, action="template.instantiate", target=inv.id,
                    detail={"template": t.name}))
    await db.commit()
    plan = (t.modules or {}).get("plan") or {}
    if data.run:
        # Collect union of modules across the subject types we actually have
        wanted = set()
        for s in data.subjects:
            for m in plan.get(s["type"], []):
                wanted.add(m)
        await enqueue_run(inv.id, sorted(wanted) if wanted else None, None)
    return {"id": inv.id}


@router.delete("/{tid}")
async def delete(tid: str, _=Depends(require_role("admin")),
                 db: AsyncSession = Depends(get_session)):
    t = await db.get(InvestigationTemplate, tid)
    if not t:
        raise HTTPException(404, "not found")
    await db.delete(t); await db.commit()
    return {"deleted": tid}
