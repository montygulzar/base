"""Elasticsearch export — bulk-index the investigation's entities and
findings into a configured ES cluster (ELASTICSEARCH_URL, optional
ELASTICSEARCH_API_KEY). Idempotent — document _id derives from entity/
finding UUID.
"""
from __future__ import annotations
import json
import httpx
from sqlalchemy import select
from ..config import get_settings
from ..db import SessionLocal
from ..models import Entity, Finding
from .base import Module, Finding as F, CollectionResult, RunContext, register


async def _bulk(c: httpx.AsyncClient, url: str, headers: dict, docs: list[dict], index: str) -> dict:
    lines = []
    for d in docs:
        lines.append(json.dumps({"index": {"_index": index, "_id": d["id"]}}))
        lines.append(json.dumps(d))
    body = "\n".join(lines) + "\n"
    r = await c.post(f"{url}/_bulk", content=body,
                     headers={**headers, "content-type": "application/x-ndjson"},
                     timeout=60)
    return {"status": r.status_code, "errors": (r.json() or {}).get("errors") if r.status_code == 200 else None,
            "bytes": len(body)}


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    s = get_settings()
    out = CollectionResult()
    url = getattr(s, "ELASTICSEARCH_URL", "") or ""
    if not url:
        out.findings.append(F("elasticsearch", "source_unavailable",
                              {"reason": "ELASTICSEARCH_URL not set"}, 0.0))
        return out
    headers = {}
    key = getattr(s, "ELASTICSEARCH_API_KEY", "") or ""
    if key:
        headers["authorization"] = f"ApiKey {key}"
    async with SessionLocal() as db:
        ents = (await db.execute(select(Entity).where(
            Entity.investigation_id == ctx.investigation_id))).scalars().all()
        finds = (await db.execute(select(Finding).where(
            Finding.investigation_id == ctx.investigation_id))).scalars().all()
    e_docs = [{"id": e.id, "investigation_id": e.investigation_id,
               "type": e.type, "value": e.value, "attributes": e.attributes,
               "confidence": e.confidence,
               "first_seen": e.first_seen.isoformat()} for e in ents]
    f_docs = [{"id": f.id, "investigation_id": f.investigation_id,
               "module": f.module, "source": f.source, "kind": f.kind,
               "data": f.data, "confidence": f.confidence,
               "collected_at": f.collected_at.isoformat()} for f in finds]
    async with httpx.AsyncClient() as c:
        try:
            r1 = await _bulk(c, url, headers, e_docs, "base-entities") if e_docs else {"status": 0}
            r2 = await _bulk(c, url, headers, f_docs, "base-findings") if f_docs else {"status": 0}
            out.findings.append(F("elasticsearch", "bulk",
                                  {"entities_sent": len(e_docs), "entities_resp": r1,
                                   "findings_sent": len(f_docs), "findings_resp": r2},
                                  0.9))
        except Exception as e:
            out.findings.append(F("elasticsearch", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="elasticsearch_export",
    name="Elasticsearch export",
    subject_types=["domain", "ip", "email", "username", "company",
                   "media", "document", "url", "phone", "btc", "eth"],
    description="Bulk-index entities + findings into ES.",
    run=run,
))
