"""Shareable read-only investigation links.

Issues a short-lived signed token scoped to a single investigation; the
`/share/{token}` endpoint returns the investigation bundle without
requiring auth.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from jose import jwt, JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import require_role
from ..config import get_settings
from ..db import get_session
from ..models import Investigation, Entity, Relationship, Finding, AuditLog

router = APIRouter()


class ShareReq(BaseModel):
    ttl_hours: int = 72


@router.post("/{inv_id}")
async def mint(inv_id: str, req: ShareReq, u=Depends(require_role("admin", "analyst")),
               db: AsyncSession = Depends(get_session)):
    s = get_settings()
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "not found")
    exp = datetime.now(timezone.utc) + timedelta(hours=max(1, min(req.ttl_hours, 720)))
    tok = jwt.encode({"inv": inv_id, "share": True, "exp": exp},
                     s.JWT_SECRET, algorithm=s.JWT_ALGO)
    db.add(AuditLog(user_id=u.id, action="share.mint", target=inv_id,
                    detail={"ttl_hours": req.ttl_hours}))
    await db.commit()
    return {"token": tok, "expires_at": exp.isoformat()}


@router.get("/{token}")
async def view(token: str, db: AsyncSession = Depends(get_session)):
    s = get_settings()
    try:
        payload = jwt.decode(token, s.JWT_SECRET, algorithms=[s.JWT_ALGO])
    except JWTError:
        raise HTTPException(401, "invalid or expired share token")
    if not payload.get("share"):
        raise HTTPException(401, "not a share token")
    inv_id = payload["inv"]
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "not found")
    ents = (await db.execute(select(Entity).where(Entity.investigation_id == inv_id))).scalars().all()
    rels = (await db.execute(select(Relationship).where(Relationship.investigation_id == inv_id))).scalars().all()
    finds = (await db.execute(select(Finding).where(Finding.investigation_id == inv_id))).scalars().all()
    return {
        "investigation": {"id": inv.id, "name": inv.name,
                          "description": inv.description, "status": inv.status},
        "entities_count": len(ents),
        "relationships_count": len(rels),
        "findings_count": len(finds),
        "entities_by_type": {},  # frontend can compute
        "preview_findings": [{"module": f.module, "source": f.source, "kind": f.kind,
                              "confidence": f.confidence,
                              "collected_at": f.collected_at.isoformat()}
                             for f in finds[:50]],
    }
