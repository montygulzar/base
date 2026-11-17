"""CSV upload bulk-ingest. Accepts a CSV with columns like value,type
(or just one column of values which get autodetected).
"""
from __future__ import annotations
import csv
import io
from fastapi import APIRouter, Depends, File, UploadFile, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import require_role
from ..db import get_session
from ..models import Investigation, Entity, AuditLog
from ..api.ingest import classify

router = APIRouter()


@router.post("/{inv_id}")
async def csv_ingest(inv_id: str, file: UploadFile = File(...),
                     u=Depends(require_role("admin", "analyst")),
                     db: AsyncSession = Depends(get_session)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "not found")
    raw = (await file.read()).decode("utf-8", errors="replace")
    reader = csv.reader(io.StringIO(raw))
    added = 0
    skipped: list[str] = []
    header = None
    for row in reader:
        if not row:
            continue
        if header is None:
            # auto-detect header
            if any(c.lower() in ("value", "type", "ioc", "indicator") for c in row):
                header = {name.lower(): i for i, name in enumerate(row)}
                continue
            header = {}
        v = row[header.get("value", 0)] if "value" in header else row[0]
        t = row[header.get("type")] if "type" in header else None
        if t:
            value = v.strip()
            kind = t.strip().lower()
            if not value:
                continue
        else:
            classified = classify(v.strip())
            if not classified:
                skipped.append(v.strip()); continue
            kind, value = classified
        q = select(Entity).where(Entity.investigation_id == inv_id,
                                 Entity.type == kind, Entity.value == value)
        if (await db.execute(q)).scalar_one_or_none():
            continue
        db.add(Entity(investigation_id=inv_id, type=kind, value=value,
                      attributes={"source": "csv_ingest"}, confidence=0.7))
        added += 1
    db.add(AuditLog(user_id=u.id, action="csv.ingest", target=inv_id,
                    detail={"added": added, "skipped_count": len(skipped)}))
    await db.commit()
    return {"added": added, "skipped": skipped[:50]}
