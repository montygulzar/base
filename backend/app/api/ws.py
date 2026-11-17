"""Live progress — minimal poller over WebSocket. Clients subscribe to an
investigation id; the server pushes job/status snapshots at a short interval.
"""
import asyncio
import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from ..db import SessionLocal
from ..models import Job, Investigation

router = APIRouter()


@router.websocket("/investigations/{inv_id}")
async def inv_ws(ws: WebSocket, inv_id: str):
    await ws.accept()
    try:
        while True:
            async with SessionLocal() as db:
                inv = await db.get(Investigation, inv_id)
                if not inv:
                    await ws.send_text(json.dumps({"error": "not_found"}))
                    await ws.close()
                    return
                jobs = (await db.execute(select(Job).where(Job.investigation_id == inv_id))).scalars().all()
                payload = {
                    "status": inv.status,
                    "jobs": [{"id": j.id, "module": j.module, "status": j.status,
                              "error": j.error, "result": j.result} for j in jobs],
                }
            await ws.send_text(json.dumps(payload))
            await asyncio.sleep(1.5)
    except WebSocketDisconnect:
        return
