import json
import io
import csv
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..models import Investigation, Subject, Job, Entity, Relationship, Finding
from ..reporting import render_markdown, render_pdf, render_html

router = APIRouter()


async def _bundle(inv_id: str, db: AsyncSession) -> dict:
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "not found")
    subs = (await db.execute(select(Subject).where(Subject.investigation_id == inv_id))).scalars().all()
    jobs = (await db.execute(select(Job).where(Job.investigation_id == inv_id))).scalars().all()
    ents = (await db.execute(select(Entity).where(Entity.investigation_id == inv_id))).scalars().all()
    rels = (await db.execute(select(Relationship).where(Relationship.investigation_id == inv_id))).scalars().all()
    finds = (await db.execute(select(Finding).where(Finding.investigation_id == inv_id))).scalars().all()
    return {
        "investigation": {"id": inv.id, "name": inv.name, "description": inv.description,
                          "status": inv.status, "created_at": inv.created_at.isoformat(),
                          "updated_at": inv.updated_at.isoformat()},
        "subjects": [{"id": s.id, "type": s.type, "value": s.value, "note": s.note} for s in subs],
        "jobs": [{"id": j.id, "module": j.module, "status": j.status, "error": j.error,
                  "started_at": j.started_at.isoformat() if j.started_at else None,
                  "finished_at": j.finished_at.isoformat() if j.finished_at else None,
                  "result": j.result} for j in jobs],
        "entities": [{"id": e.id, "type": e.type, "value": e.value,
                      "attributes": e.attributes, "confidence": e.confidence} for e in ents],
        "relationships": [{"id": r.id, "src": r.src_id, "dst": r.dst_id, "type": r.type,
                           "source": r.source, "confidence": r.confidence,
                           "evidence": r.evidence} for r in rels],
        "findings": [{"id": f.id, "module": f.module, "source": f.source, "kind": f.kind,
                      "data": f.data, "confidence": f.confidence,
                      "collected_at": f.collected_at.isoformat()} for f in finds],
    }


@router.get("/{inv_id}.json")
async def report_json(inv_id: str, _: object = Depends(current_user), db: AsyncSession = Depends(get_session)):
    return JSONResponse(await _bundle(inv_id, db))


@router.get("/{inv_id}.md")
async def report_md(inv_id: str, _: object = Depends(current_user), db: AsyncSession = Depends(get_session)):
    body = render_markdown(await _bundle(inv_id, db))
    return Response(body, media_type="text/markdown")


@router.get("/{inv_id}.html")
async def report_html(inv_id: str, _: object = Depends(current_user), db: AsyncSession = Depends(get_session)):
    body = render_html(await _bundle(inv_id, db))
    return Response(body, media_type="text/html")


@router.get("/{inv_id}.pdf")
async def report_pdf(inv_id: str, _: object = Depends(current_user), db: AsyncSession = Depends(get_session)):
    body = render_pdf(await _bundle(inv_id, db))
    return Response(body, media_type="application/pdf",
                    headers={"content-disposition": f'attachment; filename="{inv_id}.pdf"'})


@router.get("/{inv_id}.csv")
async def report_csv(inv_id: str, _: object = Depends(current_user), db: AsyncSession = Depends(get_session)):
    bundle = await _bundle(inv_id, db)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["module", "source", "kind", "confidence", "collected_at", "data"])
    for f in bundle["findings"]:
        w.writerow([f["module"], f["source"], f["kind"], f["confidence"],
                    f["collected_at"], json.dumps(f["data"], ensure_ascii=False)])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"content-disposition": f'attachment; filename="{inv_id}.csv"'})
