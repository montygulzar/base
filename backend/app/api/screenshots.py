"""Screenshot listing + direct download for an investigation."""
from __future__ import annotations
import os
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from ..auth import current_user
from ..config import get_settings

router = APIRouter()


@router.get("/{inv_id}")
async def list_shots(inv_id: str, _: object = Depends(current_user)):
    s = get_settings()
    d = Path(s.UPLOAD_DIR) / inv_id / "screenshots"
    if not d.exists():
        return {"screenshots": []}
    files = []
    for p in sorted(d.iterdir()):
        if p.suffix.lower() in (".png", ".jpg", ".jpeg", ".webp"):
            files.append({
                "name": p.name, "bytes": p.stat().st_size,
                "path": str(p),
                "download_url": f"/api/screenshots/{inv_id}/{p.name}",
            })
    return {"screenshots": files}


@router.get("/{inv_id}/{name}")
async def download(inv_id: str, name: str, _: object = Depends(current_user)):
    s = get_settings()
    # prevent path traversal
    safe = os.path.basename(name)
    p = Path(s.UPLOAD_DIR) / inv_id / "screenshots" / safe
    if not p.exists():
        raise HTTPException(404, "not found")
    return FileResponse(str(p), media_type="image/png")
