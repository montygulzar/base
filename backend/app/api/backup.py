"""Investigation backup / restore (JSON round-trip).

Dumps every subject / entity / relationship / finding / audit entry
into a single JSON bundle. Restore rehydrates into a NEW investigation
record under the caller's user, preserving values + relationships but
remapping IDs.
"""
from __future__ import annotations
import json
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import require_role, current_user
from ..db import get_session
from ..models import (Investigation, Subject, Entity, Relationship,
                       Finding, AuditLog)

router = APIRouter()


@router.get("/{inv_id}.base.json")
async def backup(inv_id: str, _: object = Depends(current_user),
                 db: AsyncSession = Depends(get_session)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "not found")
    subs = (await db.execute(select(Subject).where(Subject.investigation_id == inv_id))).scalars().all()
    ents = (await db.execute(select(Entity).where(Entity.investigation_id == inv_id))).scalars().all()
    rels = (await db.execute(select(Relationship).where(Relationship.investigation_id == inv_id))).scalars().all()
    finds = (await db.execute(select(Finding).where(Finding.investigation_id == inv_id))).scalars().all()
    return JSONResponse({
        "schema": "base.investigation.v1",
        "investigation": {"name": inv.name, "description": inv.description,
                          "status": inv.status, "created_at": inv.created_at.isoformat()},
        "subjects": [{"type": s.type, "value": s.value, "note": s.note} for s in subs],
        "entities": [{"local_id": e.id, "type": e.type, "value": e.value,
                      "attributes": e.attributes, "confidence": e.confidence} for e in ents],
        "relationships": [{"src": r.src_id, "dst": r.dst_id, "type": r.type,
                           "source": r.source, "confidence": r.confidence,
                           "evidence": r.evidence} for r in rels],
        "findings": [{"module": f.module, "source": f.source, "kind": f.kind,
                      "data": f.data, "confidence": f.confidence,
                      "entity_local_id": f.entity_id,
                      "collected_at": f.collected_at.isoformat()} for f in finds],
    })


@router.post("/restore")
async def restore(request: Request, u=Depends(require_role("admin", "analyst")),
                  db: AsyncSession = Depends(get_session)):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(400, "invalid json")
    if payload.get("schema") != "base.investigation.v1":
        raise HTTPException(400, "unsupported schema")
    inv_meta = payload.get("investigation") or {}
    inv = Investigation(name=inv_meta.get("name") or "restored",
                        description=inv_meta.get("description") or "",
                        owner_id=u.id)
    db.add(inv); await db.flush()
    for s in payload.get("subjects") or []:
        db.add(Subject(investigation_id=inv.id, type=s["type"], value=s["value"],
                       note=s.get("note", "")))
    local_to_new: dict[str, str] = {}
    for e in payload.get("entities") or []:
        ne = Entity(investigation_id=inv.id, type=e["type"], value=e["value"],
                    attributes=e.get("attributes") or {},
                    confidence=e.get("confidence") or 0.5)
        db.add(ne); await db.flush()
        if e.get("local_id"):
            local_to_new[e["local_id"]] = ne.id
    for r in payload.get("relationships") or []:
        sid = local_to_new.get(r.get("src")); did = local_to_new.get(r.get("dst"))
        if sid and did:
            db.add(Relationship(investigation_id=inv.id, src_id=sid, dst_id=did,
                                type=r["type"], source=r.get("source") or "",
                                confidence=r.get("confidence") or 0.5,
                                evidence=r.get("evidence") or {}))
    for f in payload.get("findings") or []:
        ent_id = local_to_new.get(f.get("entity_local_id"))
        db.add(Finding(investigation_id=inv.id, entity_id=ent_id,
                       module=f["module"], source=f["source"], kind=f["kind"],
                       data=f.get("data") or {}, confidence=f.get("confidence") or 0.5))
    db.add(AuditLog(user_id=u.id, action="investigation.restore", target=inv.id,
                    detail={"entities": len(local_to_new),
                            "findings": len(payload.get("findings") or [])}))
    await db.commit()
    return {"id": inv.id,
            "entities_restored": len(local_to_new),
            "findings_restored": len(payload.get("findings") or [])}
