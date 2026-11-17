"""Quick-triage — one-shot: autodetect type, create an ad-hoc
investigation, run the default plan, return the investigation id so the
caller can poll /progress.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from ..auth import require_role
from ..db import get_session
from sqlalchemy.ext.asyncio import AsyncSession
from ..models import Investigation, Subject, AuditLog
from ..queue import enqueue_run
from ..api.detect import detect, DetectIn

router = APIRouter()


class TriageIn(BaseModel):
    value: str


@router.post("")
async def triage(data: TriageIn, u=Depends(require_role("admin", "analyst")),
                 db: AsyncSession = Depends(get_session)):
    det = await detect(DetectIn(value=data.value), _=u)
    if not det.get("type"):
        raise HTTPException(400, "could not autodetect subject type")
    inv = Investigation(name=f"triage: {det['value'][:48]}",
                        description=f"auto-created from quick triage ({det['type']})",
                        owner_id=u.id)
    db.add(inv)
    await db.flush()
    sub = Subject(investigation_id=inv.id, type=det["type"], value=det["value"],
                  note="quick-triage")
    db.add(sub)
    db.add(AuditLog(user_id=u.id, action="triage", target=inv.id, detail=det))
    await db.commit()
    await enqueue_run(inv.id, None, [sub.id])
    return {"investigation_id": inv.id, "detected": det}
