"""STIX 2.1 bundle export + ingest.

Export: GET /api/stix/{inv}.stix.json
Ingest: POST /api/stix/{inv}/import — body is a STIX 2.1 bundle.

Supported observable types for export:
    domain-name, ipv4-addr, ipv6-addr, email-addr, url, file (sha-256),
    user-account, vulnerability (CVE).
"""
from __future__ import annotations
import json
import uuid as uuid_lib
from datetime import datetime
from ipaddress import ip_address
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..models import Investigation, Entity, Relationship, Finding, AuditLog

router = APIRouter()


def _stix_id(type_: str) -> str:
    return f"{type_}--{uuid_lib.uuid4()}"


def _now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _obs(e: Entity) -> dict | None:
    t = e.type
    v = e.value
    if t == "domain":
        return {"type": "domain-name", "id": _stix_id("domain-name"), "value": v}
    if t == "ip":
        try:
            a = ip_address(v)
        except ValueError:
            return None
        kind = "ipv6-addr" if a.version == 6 else "ipv4-addr"
        return {"type": kind, "id": _stix_id(kind), "value": v}
    if t == "email":
        return {"type": "email-addr", "id": _stix_id("email-addr"), "value": v}
    if t == "url":
        return {"type": "url", "id": _stix_id("url"), "value": v}
    if t == "hash" or t == "file":
        return {"type": "file", "id": _stix_id("file"), "hashes": {"SHA-256": v}}
    if t == "username":
        return {"type": "user-account", "id": _stix_id("user-account"), "account_login": v}
    if t == "cve":
        return {"type": "vulnerability", "id": _stix_id("vulnerability"), "name": v,
                "external_references": [{"source_name": "cve", "external_id": v}]}
    return None


@router.get("/{inv_id}.stix.json")
async def export_stix(inv_id: str, _: object = Depends(current_user),
                      db: AsyncSession = Depends(get_session)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "not found")
    ents = (await db.execute(select(Entity).where(Entity.investigation_id == inv_id))).scalars().all()
    rels = (await db.execute(select(Relationship).where(Relationship.investigation_id == inv_id))).scalars().all()

    objects: list[dict] = []
    identity_id = _stix_id("identity")
    objects.append({"type": "identity", "id": identity_id, "spec_version": "2.1",
                    "created": _now(), "modified": _now(), "name": "base",
                    "identity_class": "system"})

    entity_to_stix: dict[str, str] = {}
    for e in ents:
        o = _obs(e)
        if not o:
            continue
        o["spec_version"] = "2.1"
        objects.append(o)
        entity_to_stix[e.id] = o["id"]

    for r in rels:
        src = entity_to_stix.get(r.src_id)
        dst = entity_to_stix.get(r.dst_id)
        if not src or not dst:
            continue
        objects.append({
            "type": "relationship", "spec_version": "2.1",
            "id": _stix_id("relationship"),
            "created": _now(), "modified": _now(),
            "relationship_type": r.type,
            "source_ref": src, "target_ref": dst,
            "created_by_ref": identity_id,
            "description": f"base: source={r.source} conf={r.confidence:.2f}",
        })

    bundle = {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "spec_version": "2.1",
        "objects": objects,
    }
    return JSONResponse(bundle)


@router.post("/{inv_id}/import")
async def import_stix(inv_id: str, request: Request,
                      u=Depends(current_user), db: AsyncSession = Depends(get_session)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "not found")
    try:
        bundle = await request.json()
    except Exception:
        raise HTTPException(400, "invalid json")
    if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise HTTPException(400, "not a STIX bundle")

    added_ents = 0
    added_rels = 0
    stix_to_entity: dict[str, str] = {}
    for obj in bundle["objects"]:
        t = obj.get("type")
        value = None
        kind = None
        if t == "domain-name":
            value, kind = obj.get("value"), "domain"
        elif t in ("ipv4-addr", "ipv6-addr"):
            value, kind = obj.get("value"), "ip"
        elif t == "email-addr":
            value, kind = obj.get("value"), "email"
        elif t == "url":
            value, kind = obj.get("value"), "url"
        elif t == "file":
            h = (obj.get("hashes") or {}).get("SHA-256") or (obj.get("hashes") or {}).get("sha-256")
            if h:
                value, kind = h, "hash"
        elif t == "user-account":
            value, kind = obj.get("account_login") or obj.get("user_id"), "username"
        elif t == "vulnerability":
            value, kind = (obj.get("name") or "").upper(), "cve"
        if not value or not kind:
            continue
        # upsert by (inv, type, value)
        q = select(Entity).where(Entity.investigation_id == inv_id,
                                 Entity.type == kind, Entity.value == value)
        ex = (await db.execute(q)).scalar_one_or_none()
        if ex:
            stix_to_entity[obj["id"]] = ex.id
            continue
        e = Entity(investigation_id=inv_id, type=kind, value=value,
                   attributes={"stix_type": t}, confidence=0.75)
        db.add(e); await db.flush()
        stix_to_entity[obj["id"]] = e.id
        added_ents += 1

    for obj in bundle["objects"]:
        if obj.get("type") != "relationship":
            continue
        s, dst = obj.get("source_ref"), obj.get("target_ref")
        sid = stix_to_entity.get(s)
        did = stix_to_entity.get(dst)
        if not sid or not did:
            continue
        db.add(Relationship(investigation_id=inv_id, src_id=sid, dst_id=did,
                            type=obj.get("relationship_type", "related-to"),
                            source="stix_import", confidence=0.7,
                            evidence={"stix_id": obj.get("id")}))
        added_rels += 1

    db.add(AuditLog(user_id=u.id, action="stix.import", target=inv_id,
                    detail={"entities": added_ents, "relationships": added_rels}))
    await db.commit()
    return {"added_entities": added_ents, "added_relationships": added_rels}
