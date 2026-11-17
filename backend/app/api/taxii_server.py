"""TAXII 2.1 server mode.

Each investigation is exposed as a collection. OpenCTI / other TAXII
clients can subscribe and pull STIX bundles that we build on the fly
from our stored entities + relationships.
"""
from __future__ import annotations
from datetime import datetime
import uuid as uuid_lib
from ipaddress import ip_address
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..models import Investigation, Entity, Relationship


router = APIRouter()


def _now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _sid(t): return f"{t}--{uuid_lib.uuid4()}"


@router.get("/discovery")
async def discovery(_: object = Depends(current_user)):
    return {
        "title": "base TAXII server",
        "description": "Each investigation is a TAXII collection.",
        "contact": "base",
        "default": "/api/taxii_server/api_root/",
        "api_roots": ["/api/taxii_server/api_root/"],
    }


@router.get("/api_root/collections/")
async def collections(_: object = Depends(current_user), db: AsyncSession = Depends(get_session)):
    rows = (await db.execute(select(Investigation))).scalars().all()
    return {"collections": [{"id": r.id, "title": r.name,
                              "can_read": True, "can_write": False,
                              "media_types": ["application/taxii+json;version=2.1"]} for r in rows]}


@router.get("/api_root/collections/{cid}/objects/")
async def objects(cid: str, _: object = Depends(current_user),
                  db: AsyncSession = Depends(get_session)):
    inv = await db.get(Investigation, cid)
    if not inv:
        raise HTTPException(404, "collection not found")
    ents = (await db.execute(select(Entity).where(Entity.investigation_id == cid))).scalars().all()
    rels = (await db.execute(select(Relationship).where(Relationship.investigation_id == cid))).scalars().all()
    objs: list[dict] = []
    idx: dict[str, str] = {}
    for e in ents:
        if e.type == "domain":
            o = {"type": "domain-name", "id": _sid("domain-name"), "value": e.value}
        elif e.type == "ip":
            try:
                a = ip_address(e.value); kind = "ipv6-addr" if a.version == 6 else "ipv4-addr"
            except ValueError:
                continue
            o = {"type": kind, "id": _sid(kind), "value": e.value}
        elif e.type == "email":
            o = {"type": "email-addr", "id": _sid("email-addr"), "value": e.value}
        elif e.type == "url":
            o = {"type": "url", "id": _sid("url"), "value": e.value}
        elif e.type == "hash":
            o = {"type": "file", "id": _sid("file"), "hashes": {"SHA-256": e.value}}
        elif e.type == "username":
            o = {"type": "user-account", "id": _sid("user-account"), "account_login": e.value}
        elif e.type == "cve":
            o = {"type": "vulnerability", "id": _sid("vulnerability"), "name": e.value}
        else:
            continue
        o["spec_version"] = "2.1"
        objs.append(o); idx[e.id] = o["id"]
    for r in rels:
        s, t = idx.get(r.src_id), idx.get(r.dst_id)
        if not s or not t:
            continue
        objs.append({"type": "relationship", "spec_version": "2.1",
                     "id": _sid("relationship"),
                     "created": _now(), "modified": _now(),
                     "relationship_type": r.type,
                     "source_ref": s, "target_ref": t})
    return JSONResponse({"objects": objs, "more": False})
