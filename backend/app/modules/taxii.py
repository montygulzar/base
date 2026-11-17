"""TAXII 2.1 poll — pull STIX objects from a configured TAXII server
collection and ingest into the current investigation.

Runs when subject is a TAXII collection URL formatted as
`taxii:<root>:<collection_id>`. The caller provides creds via subject
`note` field as a username:password string, if the server needs auth.
"""
from __future__ import annotations
import httpx
from ..config import get_settings
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    if not v.startswith("taxii:"):
        out.findings.append(Finding("taxii", "invalid_input",
                                    {"expected": "taxii:<root_url>:<collection_id>"}, 0.1))
        return out
    try:
        _, root, cid = v.split(":", 2)
    except ValueError:
        out.findings.append(Finding("taxii", "invalid_input",
                                    {"expected": "taxii:<root_url>:<collection_id>"}, 0.1))
        return out
    headers = {"accept": "application/taxii+json;version=2.1",
               "user-agent": "base-osint/0.1"}
    async with httpx.AsyncClient(headers=headers) as c:
        try:
            r = await c.get(f"{root.rstrip('/')}/collections/{cid}/objects/", timeout=30)
            if r.status_code != 200:
                out.findings.append(Finding("taxii", "http_error",
                                            {"status": r.status_code, "body": r.text[:200]}, 0.1))
                return out
            bundle = r.json()
            objs = bundle.get("objects") or []
            out.findings.append(Finding("taxii", "poll",
                                        {"root": root, "collection": cid, "count": len(objs)}, 0.9))
            for obj in objs:
                t = obj.get("type")
                if t == "indicator":
                    pattern = obj.get("pattern") or ""
                    out.findings.append(Finding("taxii", "indicator",
                                                {"pattern": pattern, "name": obj.get("name"),
                                                 "labels": obj.get("labels"),
                                                 "id": obj.get("id")}, 0.85))
                    # minimal pattern extraction
                    import re
                    for kind, rx in [
                        ("ip", r"ipv4-addr:value\s*=\s*'([^']+)'"),
                        ("domain", r"domain-name:value\s*=\s*'([^']+)'"),
                        ("url", r"url:value\s*=\s*'([^']+)'"),
                        ("email", r"email-addr:value\s*=\s*'([^']+)'"),
                        ("hash", r"file:hashes\.(?:SHA-256|'SHA-256')\s*=\s*'([^']+)'"),
                    ]:
                        for m in re.findall(rx, pattern):
                            out.entities.append(Entity(kind, m, {"from": "taxii"}, 0.8))
        except Exception as e:
            out.findings.append(Finding("taxii", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="taxii",
    name="TAXII 2.1 poll",
    subject_types=["url"],
    description="Pulls STIX objects from a TAXII 2.1 collection.",
    run=run,
))
