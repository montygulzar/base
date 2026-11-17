"""Export an investigation as a MISP event (JSON).

Translates entities into MISP attributes with reasonable type mappings.
Importable into any MISP instance that accepts v2 event JSON.
"""
from __future__ import annotations
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..models import Investigation, Entity

TYPE_MAP = {
    "ip":      ("ip-dst",       "Network activity"),
    "domain":  ("domain",       "Network activity"),
    "url":     ("url",          "Network activity"),
    "email":   ("email",        "Social network"),
    "hash":    ("sha256",       "Payload delivery"),
    "cve":     ("vulnerability","External analysis"),
    "username":("github-username","Social network"),
    "org":     ("comment",      "Other"),
    "asn":     ("AS",           "Network activity"),
}

router = APIRouter()


@router.get("/{inv_id}.misp.json")
async def misp_event(inv_id: str, _: object = Depends(current_user), db: AsyncSession = Depends(get_session)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "not found")
    ents = (await db.execute(select(Entity).where(Entity.investigation_id == inv_id))).scalars().all()

    attributes = []
    for e in ents:
        mapped = TYPE_MAP.get(e.type)
        if not mapped:
            continue
        t, cat = mapped
        attributes.append({
            "uuid": e.id,
            "type": t,
            "category": cat,
            "to_ids": e.confidence >= 0.7,
            "value": e.value,
            "comment": f"base entity (conf={e.confidence:.2f})",
            "timestamp": str(int(datetime.utcnow().timestamp())),
        })

    event = {
        "Event": {
            "uuid": inv.id,
            "info": inv.name,
            "date": datetime.utcnow().strftime("%Y-%m-%d"),
            "analysis": "1",
            "threat_level_id": "3",
            "distribution": "0",
            "published": False,
            "Attribute": attributes,
            "Tag": [{"name": "base:source=automated"}],
            "org_name": "base",
        }
    }
    return JSONResponse(event)
