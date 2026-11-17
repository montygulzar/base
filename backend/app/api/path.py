"""Shortest path between two entities in an investigation's graph.

Treats the graph as undirected (OSINT pivots often need to walk edges in
either direction). BFS, capped at depth 8.
"""
from __future__ import annotations
from collections import deque
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..models import Entity, Relationship

router = APIRouter()


@router.get("/{inv_id}")
async def path(inv_id: str, src: str, dst: str, max_depth: int = 8,
               _: object = Depends(current_user),
               db: AsyncSession = Depends(get_session)):
    """`src` / `dst` are entity ids OR 'type:value' strings."""
    async def _resolve(ref: str) -> Entity | None:
        if ":" in ref and len(ref) < 300:
            t, v = ref.split(":", 1)
            return (await db.execute(select(Entity).where(
                Entity.investigation_id == inv_id,
                Entity.type == t, Entity.value == v))).scalar_one_or_none()
        return await db.get(Entity, ref)

    a, b = await _resolve(src), await _resolve(dst)
    if not a or not b or a.investigation_id != inv_id or b.investigation_id != inv_id:
        raise HTTPException(404, "src or dst not found")
    rels = (await db.execute(select(Relationship).where(
        Relationship.investigation_id == inv_id))).scalars().all()
    adj: dict[str, list[tuple[str, str]]] = {}
    for r in rels:
        adj.setdefault(r.src_id, []).append((r.dst_id, r.id))
        adj.setdefault(r.dst_id, []).append((r.src_id, r.id))
    # BFS
    parent: dict[str, tuple[str, str]] = {}
    q = deque([(a.id, 0)])
    seen = {a.id}
    found = False
    while q:
        cur, depth = q.popleft()
        if cur == b.id:
            found = True; break
        if depth >= max_depth:
            continue
        for nxt, rel_id in adj.get(cur, []):
            if nxt in seen:
                continue
            seen.add(nxt)
            parent[nxt] = (cur, rel_id)
            q.append((nxt, depth + 1))
    if not found:
        return {"found": False, "max_depth": max_depth,
                "visited": len(seen)}
    # reconstruct
    nodes_path = [b.id]
    edges_path = []
    cur = b.id
    while cur in parent:
        prev, rel_id = parent[cur]
        edges_path.append(rel_id)
        nodes_path.append(prev)
        cur = prev
    nodes_path.reverse(); edges_path.reverse()
    node_entities = {e.id: e for e in (await db.execute(
        select(Entity).where(Entity.id.in_(nodes_path)))).scalars().all()}
    edge_rels = {r.id: r for r in (await db.execute(
        select(Relationship).where(Relationship.id.in_(edges_path)))).scalars().all()}
    return {
        "found": True,
        "length": len(edges_path),
        "nodes": [{"id": nid, "type": node_entities[nid].type,
                   "value": node_entities[nid].value} for nid in nodes_path if nid in node_entities],
        "edges": [{"id": eid, "type": edge_rels[eid].type,
                   "source_label": edge_rels[eid].source,
                   "confidence": edge_rels[eid].confidence} for eid in edges_path if eid in edge_rels],
    }
