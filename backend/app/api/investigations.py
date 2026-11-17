import asyncio
import os
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user, require_role
from ..db import get_session
from ..config import get_settings
from ..models import User, Investigation, Subject, Job, Finding, AuditLog
from ..schemas import InvestigationCreate, InvestigationOut, SubjectIn, SubjectOut, JobOut, FindingOut, RunRequest
from ..orchestrator import plan_and_run
from ..queue import enqueue_run

router = APIRouter()


@router.post("", response_model=InvestigationOut)
async def create(data: InvestigationCreate, u: User = Depends(require_role("admin", "analyst")),
                 db: AsyncSession = Depends(get_session)):
    inv = Investigation(name=data.name, description=data.description, owner_id=u.id)
    db.add(inv); await db.flush()
    for s in data.subjects:
        db.add(Subject(investigation_id=inv.id, type=s.type, value=s.value, note=s.note))
    db.add(AuditLog(user_id=u.id, action="investigation.create", target=inv.id, detail={"name": inv.name}))
    await db.commit(); await db.refresh(inv)
    return inv


@router.get("", response_model=list[InvestigationOut])
async def list_all(u: User = Depends(current_user), db: AsyncSession = Depends(get_session)):
    rows = (await db.execute(select(Investigation).order_by(Investigation.updated_at.desc()))).scalars().all()
    return rows


@router.get("/{inv_id}", response_model=InvestigationOut)
async def get_one(inv_id: str, _: User = Depends(current_user), db: AsyncSession = Depends(get_session)):
    inv = await db.get(Investigation, inv_id)
    if not inv: raise HTTPException(404, "not found")
    return inv


@router.delete("/{inv_id}")
async def delete(inv_id: str, u: User = Depends(require_role("admin")), db: AsyncSession = Depends(get_session)):
    inv = await db.get(Investigation, inv_id)
    if not inv: raise HTTPException(404, "not found")
    await db.delete(inv)
    db.add(AuditLog(user_id=u.id, action="investigation.delete", target=inv_id))
    await db.commit()
    return {"deleted": inv_id}


@router.post("/{inv_id}/subjects", response_model=SubjectOut)
async def add_subject(inv_id: str, data: SubjectIn, u: User = Depends(require_role("admin", "analyst")),
                      db: AsyncSession = Depends(get_session)):
    inv = await db.get(Investigation, inv_id)
    if not inv: raise HTTPException(404, "not found")
    s = Subject(investigation_id=inv_id, type=data.type, value=data.value, note=data.note)
    db.add(s); db.add(AuditLog(user_id=u.id, action="subject.add", target=inv_id, detail={"type": data.type, "value": data.value}))
    await db.commit(); await db.refresh(s)
    return s


@router.get("/{inv_id}/subjects", response_model=list[SubjectOut])
async def list_subjects(inv_id: str, _: User = Depends(current_user), db: AsyncSession = Depends(get_session)):
    return (await db.execute(select(Subject).where(Subject.investigation_id == inv_id))).scalars().all()


@router.post("/{inv_id}/upload")
async def upload(inv_id: str, kind: str = Form(...), file: UploadFile = File(...),
                 u: User = Depends(require_role("admin", "analyst")), db: AsyncSession = Depends(get_session)):
    """Uploads are stored under UPLOAD_DIR/<inv_id>/ and added as a subject
    of type media|document pointing to the local absolute path."""
    s = get_settings()
    inv = await db.get(Investigation, inv_id)
    if not inv: raise HTTPException(404, "not found")
    if kind not in ("media", "document"):
        raise HTTPException(400, "kind must be media|document")
    d = Path(s.UPLOAD_DIR) / inv_id
    d.mkdir(parents=True, exist_ok=True)
    # sanitise name
    safe = os.path.basename(file.filename or "file.bin").replace("..", "_")
    p = d / safe
    with p.open("wb") as fh:
        while chunk := await file.read(1 << 20):
            fh.write(chunk)
    sub = Subject(investigation_id=inv_id, type=kind, value=str(p), note=f"uploaded:{file.filename}")
    db.add(sub); db.add(AuditLog(user_id=u.id, action="file.upload", target=inv_id,
                                 detail={"name": safe, "size": p.stat().st_size}))
    await db.commit(); await db.refresh(sub)
    return {"subject_id": sub.id, "path": str(p), "size": p.stat().st_size}


@router.post("/{inv_id}/run")
async def run(inv_id: str, req: RunRequest,
              u: User = Depends(require_role("admin", "analyst")), db: AsyncSession = Depends(get_session)):
    inv = await db.get(Investigation, inv_id)
    if not inv: raise HTTPException(404, "not found")
    db.add(AuditLog(user_id=u.id, action="investigation.run", target=inv_id,
                    detail={"modules": req.modules, "subject_ids": req.subject_ids}))
    await db.commit()
    await enqueue_run(inv_id, req.modules, req.subject_ids)
    return {"status": "scheduled", "investigation_id": inv_id}


@router.get("/{inv_id}/jobs", response_model=list[JobOut])
async def jobs(inv_id: str, _: User = Depends(current_user), db: AsyncSession = Depends(get_session)):
    return (await db.execute(select(Job).where(Job.investigation_id == inv_id).order_by(Job.created_at.desc()))).scalars().all()


@router.get("/{inv_id}/findings", response_model=list[FindingOut])
async def findings(inv_id: str, module: str | None = None, source: str | None = None,
                   _: User = Depends(current_user), db: AsyncSession = Depends(get_session)):
    q = select(Finding).where(Finding.investigation_id == inv_id)
    if module: q = q.where(Finding.module == module)
    if source: q = q.where(Finding.source == source)
    q = q.order_by(Finding.collected_at.desc()).limit(2000)
    return (await db.execute(q)).scalars().all()
