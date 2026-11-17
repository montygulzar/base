"""Additional graph exports — GraphML (Gephi/yEd/Maltego) and GEXF (Gephi)."""
from __future__ import annotations
import xml.sax.saxutils as sx
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..models import Investigation, Entity, Relationship

router = APIRouter()


async def _graph(inv_id: str, db: AsyncSession):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "not found")
    ents = (await db.execute(select(Entity).where(Entity.investigation_id == inv_id))).scalars().all()
    rels = (await db.execute(select(Relationship).where(Relationship.investigation_id == inv_id))).scalars().all()
    return inv, ents, rels


@router.get("/{inv_id}.graphml")
async def graphml(inv_id: str, _: object = Depends(current_user), db: AsyncSession = Depends(get_session)):
    _, ents, rels = await _graph(inv_id, db)
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
        '<key id="type" for="node" attr.name="type" attr.type="string"/>',
        '<key id="value" for="node" attr.name="value" attr.type="string"/>',
        '<key id="conf" for="node" attr.name="confidence" attr.type="double"/>',
        '<key id="rtype" for="edge" attr.name="type" attr.type="string"/>',
        '<key id="rsrc" for="edge" attr.name="source" attr.type="string"/>',
        '<graph edgedefault="directed">',
    ]
    for e in ents:
        lines.append(
            f'<node id="{sx.escape(e.id)}">'
            f'<data key="type">{sx.escape(e.type)}</data>'
            f'<data key="value">{sx.escape(e.value)}</data>'
            f'<data key="conf">{e.confidence:.2f}</data>'
            f'</node>'
        )
    for r in rels:
        lines.append(
            f'<edge source="{sx.escape(r.src_id)}" target="{sx.escape(r.dst_id)}">'
            f'<data key="rtype">{sx.escape(r.type)}</data>'
            f'<data key="rsrc">{sx.escape(r.source)}</data>'
            f'</edge>'
        )
    lines.append("</graph></graphml>")
    return Response("\n".join(lines), media_type="application/xml",
                    headers={"content-disposition": f'attachment; filename="{inv_id}.graphml"'})


@router.get("/{inv_id}.gexf")
async def gexf(inv_id: str, _: object = Depends(current_user), db: AsyncSession = Depends(get_session)):
    inv, ents, rels = await _graph(inv_id, db)
    from datetime import datetime
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<gexf xmlns="http://www.gexf.net/1.2draft" version="1.2">',
        f'<meta lastmodifieddate="{datetime.utcnow().strftime("%Y-%m-%d")}">',
        f'<creator>base</creator><description>{sx.escape(inv.name)}</description></meta>',
        '<graph defaultedgetype="directed">',
        '<attributes class="node"><attribute id="0" title="type" type="string"/>',
        '<attribute id="1" title="confidence" type="double"/></attributes>',
        '<nodes>',
    ]
    for e in ents:
        lines.append(
            f'<node id="{sx.escape(e.id)}" label="{sx.escape(e.value)}">'
            f'<attvalues><attvalue for="0" value="{sx.escape(e.type)}"/>'
            f'<attvalue for="1" value="{e.confidence:.2f}"/></attvalues></node>'
        )
    lines.append("</nodes><edges>")
    for i, r in enumerate(rels):
        lines.append(
            f'<edge id="{i}" source="{sx.escape(r.src_id)}" target="{sx.escape(r.dst_id)}" '
            f'label="{sx.escape(r.type)}"/>'
        )
    lines.append("</edges></graph></gexf>")
    return Response("\n".join(lines), media_type="application/xml",
                    headers={"content-disposition": f'attachment; filename="{inv_id}.gexf"'})
