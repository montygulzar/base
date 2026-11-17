"""One-shot ZIP bundle: every export format for an investigation."""
from __future__ import annotations
import io
import json
import zipfile
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..models import Investigation
from .reports import _bundle, render_markdown, render_html, render_pdf
from .stix import export_stix
from .misp import misp_event
from .exports import graphml, gexf
from .geojson import geojson

router = APIRouter()


@router.get("/{inv_id}.zip")
async def zip_bundle(inv_id: str, u=Depends(current_user),
                     db: AsyncSession = Depends(get_session)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "not found")
    bundle = await _bundle(inv_id, db)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("report.json", json.dumps(bundle, indent=2, default=str))
        z.writestr("report.md", render_markdown(bundle))
        z.writestr("report.html", render_html(bundle))
        z.writestr("report.pdf", render_pdf(bundle))
        import csv as _csv
        cio = io.StringIO()
        w = _csv.writer(cio)
        w.writerow(["module", "source", "kind", "confidence", "collected_at", "data"])
        for f in bundle["findings"]:
            w.writerow([f["module"], f["source"], f["kind"], f["confidence"],
                        f["collected_at"], json.dumps(f["data"], ensure_ascii=False)])
        z.writestr("report.csv", cio.getvalue())
        # stix
        stix_resp = await export_stix(inv_id, _=u, db=db)
        z.writestr("stix.json", stix_resp.body)
        # misp
        misp_resp = await misp_event(inv_id, _=u, db=db)
        z.writestr("misp.json", misp_resp.body)
        # graphml / gexf
        g_resp = await graphml(inv_id, _=u, db=db)
        z.writestr("graph.graphml", g_resp.body)
        gx_resp = await gexf(inv_id, _=u, db=db)
        z.writestr("graph.gexf", gx_resp.body)
        # geojson
        ge_resp = await geojson(inv_id, _=u, db=db)
        z.writestr("locations.geojson", ge_resp.body)
    buf.seek(0)
    return StreamingResponse(buf, media_type="application/zip",
                             headers={"content-disposition": f'attachment; filename="{inv_id}.zip"'})
