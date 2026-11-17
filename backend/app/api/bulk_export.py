"""Bulk investigation export — zip every investigation's JSON backup."""
from __future__ import annotations
import io
import json
import zipfile
from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import require_role
from ..db import get_session
from ..models import Investigation
from .backup import backup

router = APIRouter()


@router.get(".zip")
async def bulk(u=Depends(require_role("admin")), db: AsyncSession = Depends(get_session)):
    invs = (await db.execute(select(Investigation))).scalars().all()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for inv in invs:
            resp = await backup(inv.id, _=u, db=db)
            z.writestr(f"{inv.id}.base.json", resp.body)
    buf.seek(0)
    return StreamingResponse(buf, media_type="application/zip",
                             headers={"content-disposition": 'attachment; filename="all-investigations.zip"'})
