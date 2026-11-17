"""OpenCTI push. Submits investigation entities as STIX bundle to a
configured OpenCTI GraphQL endpoint.

Env:
    OPENCTI_URL    e.g. https://opencti.example.org
    OPENCTI_TOKEN  bearer token

Subject is the investigation id. Runs standalone (no graph traversal) —
the API endpoint below builds the bundle and sends it.
"""
from __future__ import annotations
import httpx
from ..config import get_settings
from ..db import SessionLocal
from ..models import Investigation, Entity, Relationship
from sqlalchemy import select
from .base import Module, Finding, CollectionResult, RunContext, register


MUTATION = """
mutation BundleImport($file: Upload!) {
  stixCoreObjectEdit(id: "import") { ask(file: $file) }
}
"""


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    s = get_settings()
    out = CollectionResult()
    url = getattr(s, "OPENCTI_URL", "") or ""
    token = getattr(s, "OPENCTI_TOKEN", "") or ""
    if not url or not token:
        out.findings.append(Finding("opencti", "source_unavailable",
                                    {"reason": "OPENCTI_URL / OPENCTI_TOKEN not set"}, 0.0))
        return out
    inv_id = subject
    async with SessionLocal() as db:
        inv = await db.get(Investigation, inv_id)
        if not inv:
            out.findings.append(Finding("opencti", "invalid_input",
                                        {"investigation_id": inv_id, "reason": "not found"}, 0.1))
            return out
        ents = (await db.execute(select(Entity).where(Entity.investigation_id == inv_id))).scalars().all()
        rels = (await db.execute(select(Relationship).where(Relationship.investigation_id == inv_id))).scalars().all()

    # Build a STIX 2.1 bundle (lightweight — opencti is lenient)
    import uuid as uuid_lib
    from datetime import datetime

    def sid(t): return f"{t}--{uuid_lib.uuid4()}"
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    objs = []
    idx = {}
    for e in ents:
        mapping = {
            "domain": "domain-name", "ip": "ipv4-addr", "email": "email-addr",
            "url": "url", "hash": "file", "username": "user-account",
            "cve": "vulnerability",
        }
        kind = mapping.get(e.type)
        if not kind:
            continue
        o = {"type": kind, "id": sid(kind), "spec_version": "2.1"}
        if kind == "file":
            o["hashes"] = {"SHA-256": e.value}
        elif kind == "user-account":
            o["account_login"] = e.value
        elif kind == "vulnerability":
            o["name"] = e.value
        else:
            o["value"] = e.value
        objs.append(o); idx[e.id] = o["id"]
    for r in rels:
        s_, t_ = idx.get(r.src_id), idx.get(r.dst_id)
        if not s_ or not t_:
            continue
        objs.append({"type": "relationship", "spec_version": "2.1", "id": sid("relationship"),
                     "created": now, "modified": now,
                     "relationship_type": r.type, "source_ref": s_, "target_ref": t_})
    bundle = {"type": "bundle", "id": sid("bundle"), "spec_version": "2.1", "objects": objs}

    async with httpx.AsyncClient() as c:
        try:
            r = await c.post(f"{url.rstrip('/')}/graphql",
                             headers={"authorization": f"Bearer {token}",
                                      "content-type": "application/json"},
                             json={"query": "mutation { importBundle(bundle: null) }"},
                             timeout=30)
            # Simpler path: POST bundle to the REST import endpoint
            r2 = await c.post(f"{url.rstrip('/')}/graphql",
                              headers={"authorization": f"Bearer {token}"},
                              files={"file": ("bundle.json", str(bundle), "application/json")},
                              timeout=30)
            out.findings.append(Finding("opencti", "push",
                                        {"bundle_objects": len(objs),
                                         "graphql_status": r.status_code,
                                         "upload_status": r2.status_code}, 0.85))
        except Exception as e:
            out.findings.append(Finding("opencti", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="opencti_push",
    name="OpenCTI push",
    subject_types=["company", "domain", "ip", "email", "url", "username", "document", "media", "phone"],
    description="Export the investigation as STIX 2.1 and push to configured OpenCTI.",
    run=run,
))
