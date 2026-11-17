"""MITRE ATT&CK mapping.

Loads the MITRE Enterprise ATT&CK STIX bundle (public) and scans existing
investigation findings for T-ID references (T1059, T1566, …). Promotes
each technique to a `ttp` entity with name + tactic. Falls back to
source_unavailable if bundle can't be fetched.
"""
from __future__ import annotations
import re
import httpx
from sqlalchemy import select
from ..db import SessionLocal
from ..models import Finding
from .base import Module, Finding as F, Entity, Relationship, CollectionResult, RunContext, register

ATTACK_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
              "master/enterprise-attack/enterprise-attack.json")
TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


async def _load_attack_index(c: httpx.AsyncClient) -> dict[str, dict]:
    try:
        r = await c.get(ATTACK_URL, timeout=30)
        if r.status_code != 200:
            return {}
        bundle = r.json()
        idx: dict[str, dict] = {}
        for o in bundle.get("objects", []):
            if o.get("type") != "attack-pattern":
                continue
            for ref in o.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tid = ref.get("external_id")
                    if tid:
                        idx[tid] = {
                            "name": o.get("name"),
                            "description": (o.get("description") or "")[:500],
                            "kill_chain_phases": [p.get("phase_name") for p in o.get("kill_chain_phases", [])],
                            "url": ref.get("url"),
                        }
        return idx
    except Exception:
        return {}


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        idx = await _load_attack_index(c)
    if not idx:
        out.findings.append(Finding := None)  # noqa
        out.findings.append(F("mitre", "source_unavailable",
                              {"reason": "could not fetch attack bundle"}, 0.0))
        return out

    # Walk this investigation's findings; extract T-IDs from stringified data
    async with SessionLocal() as db:
        finds = (await db.execute(
            select(Finding).where(Finding.investigation_id == ctx.investigation_id)
        )).scalars().all()
    seen: dict[str, int] = {}
    for f in finds:
        for m in TID_RE.findall(str(f.data)):
            seen[m] = seen.get(m, 0) + 1
    out.findings.append(F("mitre", "seen",
                          {"loaded_techniques": len(idx), "matched": len(seen),
                           "counts": seen}, 0.9 if seen else 0.5))
    for tid, count in seen.items():
        info = idx.get(tid, {})
        out.entities.append(Entity("ttp", tid, {
            "name": info.get("name"), "tactics": info.get("kill_chain_phases"),
            "url": info.get("url"), "count": count,
        }, 0.9))
    return out


register(Module(
    key="mitre",
    name="MITRE ATT&CK mapping",
    subject_types=["domain", "ip", "email", "url", "document", "username",
                   "media", "company", "phone"],
    description="Maps technique IDs seen anywhere in findings to ATT&CK entities.",
    run=run,
))
