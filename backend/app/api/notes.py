"""Entity notes / tags — analyst annotations attached to graph nodes."""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import require_role, current_user
from ..db import get_session
from ..models import EntityNote, Entity

router = APIRouter()


class NoteIn(BaseModel):
    tags: list[str] = []
    note: str = ""


@router.post("/{entity_id}")
async def add(entity_id: str, data: NoteIn, u=Depends(require_role("admin", "analyst")),
              db: AsyncSession = Depends(get_session)):
    ent = await db.get(Entity, entity_id)
    if not ent:
        raise HTTPException(404, "entity not found")
    n = EntityNote(entity_id=entity_id, user_id=u.id,
                   tags={"list": data.tags}, note=data.note)
    db.add(n); await db.commit(); await db.refresh(n)
    return {"id": n.id}


@router.get("/{entity_id}")
async def list_notes(entity_id: str, _: object = Depends(current_user),
                     db: AsyncSession = Depends(get_session)):
    rows = (await db.execute(
        select(EntityNote).where(EntityNote.entity_id == entity_id).order_by(EntityNote.created_at.desc())
    )).scalars().all()
    return [{"id": r.id, "user_id": r.user_id, "tags": (r.tags or {}).get("list", []),
             "note": r.note, "created_at": r.created_at.isoformat()} for r in rows]


@router.delete("/{note_id}")
async def delete(note_id: str, u=Depends(require_role("admin", "analyst")),
                 db: AsyncSession = Depends(get_session)):
    n = await db.get(EntityNote, note_id)
    if not n:
        raise HTTPException(404, "not found")
    await db.delete(n); await db.commit()
    return {"deleted": note_id}
