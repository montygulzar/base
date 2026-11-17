"""Collection orchestrator. Builds a plan from an investigation's subjects,
executes modules concurrently (bounded), persists findings and feeds the
correlation engine.
"""
from __future__ import annotations
import asyncio
import logging
from datetime import datetime
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from .config import get_settings
from .db import SessionLocal
from .models import Investigation, Subject, Job, Entity as EntityModel, Relationship as RelModel, Finding as FindingModel
from .modules import REGISTRY
from .modules.base import RunContext, CollectionResult
from . import correlation

log = logging.getLogger("orchestrator")

# default module selection per subject type
PLAN: dict[str, list[str]] = {
    "domain":   ["domain", "web", "cti", "censys", "urlscan", "passive_dns", "wayback",
                 "metagoofil", "intelx", "fofa", "zoomeye", "typosquat", "favicon", "abuse_ch",
                 "dns_auth", "screenshot", "cert_pivot", "bugbounty", "certspotter",
                 "tranco", "security_txt", "opengraph", "phishing_feeds", "dnssec_axfr", "csp",
                 "robtex", "caa", "github_dorks", "archive_whois", "spamhaus_dbl",
                 "takeover", "secrets_scan", "risk", "favicon_cluster"],
    "url":      ["web", "domain", "cti", "urlscan", "crawler", "favicon", "abuse_ch",
                 "screenshot", "url_unshorten", "url_liveness"],
    "ip":       ["ip", "cti", "censys", "intelx", "internetdb", "fofa", "zoomeye", "port_probe",
                 "abuse_ch", "crowdsec", "blocklists", "robtex", "dnsbl", "ipapi",
                 "cloud_provider", "asn_prefixes"],
    "email":    ["email", "intelx", "dns_auth", "gravatar", "emailrep", "hibp_pastes", "pgp_keys"],
    "username": ["username", "intelx", "github_user", "bluesky", "mastodon", "reddit_user"],
    "company":  ["company", "opensanctions", "ahmia", "s3_enum", "cloud_bucket"],
    "media":    ["media", "reverse_image"],
    "document": ["documents", "cti", "abuse_ch"],
    "phone":    ["phone"],
}


async def _get_or_create_entity(db: AsyncSession, inv_id: str, type_: str, value: str, attributes: dict, confidence: float) -> EntityModel:
    q = select(EntityModel).where(EntityModel.investigation_id == inv_id,
                                  EntityModel.type == type_, EntityModel.value == value)
    e = (await db.execute(q)).scalar_one_or_none()
    if e:
        e.attributes = {**(e.attributes or {}), **(attributes or {})}
        e.confidence = max(e.confidence, confidence)
        return e
    e = EntityModel(investigation_id=inv_id, type=type_, value=value,
                    attributes=attributes or {}, confidence=confidence)
    db.add(e)
    await db.flush()
    return e


async def _persist(db: AsyncSession, inv_id: str, job: Job, result: CollectionResult):
    index: dict[tuple[str, str], str] = {}
    for ent in result.entities:
        e = await _get_or_create_entity(db, inv_id, ent.type, ent.value, ent.attributes, ent.confidence)
        index[(ent.type, ent.value)] = e.id

    for f in result.findings:
        db.add(FindingModel(investigation_id=inv_id, job_id=job.id,
                            module=job.module, source=f.source, kind=f.kind,
                            data=f.data, confidence=f.confidence))

    for r in result.relationships:
        sid = index.get((r.src_type, r.src_value)) or (await _get_or_create_entity(
            db, inv_id, r.src_type, r.src_value, {}, 0.6)).id
        did = index.get((r.dst_type, r.dst_value)) or (await _get_or_create_entity(
            db, inv_id, r.dst_type, r.dst_value, {}, 0.6)).id
        db.add(RelModel(investigation_id=inv_id, src_id=sid, dst_id=did,
                        type=r.type, source=r.source, confidence=r.confidence,
                        evidence=r.evidence))


async def _run_job(sem: asyncio.Semaphore, job_id: str):
    s = get_settings()
    async with sem:
        async with SessionLocal() as db:
            job = await db.get(Job, job_id)
            if not job:
                return
            subject = await db.get(Subject, job.subject_id) if job.subject_id else None
            if not subject:
                job.status = "error"
                job.error = "subject missing"
                await db.commit()
                return
            mod = REGISTRY.get(job.module)
            if not mod:
                job.status = "error"
                job.error = f"unknown module {job.module}"
                await db.commit()
                return
            job.status = "running"
            job.started_at = datetime.utcnow()
            await db.commit()
            try:
                ctx = RunContext(investigation_id=job.investigation_id, subject_id=subject.id, settings=s)
                result = await mod.run(subject.value, ctx)
                await _persist(db, job.investigation_id, job, result)
                job.status = "done"
                job.result = {"findings": len(result.findings),
                              "entities": len(result.entities),
                              "relationships": len(result.relationships)}
            except Exception as e:
                log.exception("job %s failed", job.id)
                job.status = "error"
                job.error = str(e)
            job.finished_at = datetime.utcnow()
            await db.commit()


async def plan_and_run(investigation_id: str, module_keys: list[str] | None = None,
                       subject_ids: list[str] | None = None) -> list[str]:
    s = get_settings()
    async with SessionLocal() as db:
        inv = await db.get(Investigation, investigation_id)
        if not inv:
            return []
        subs = (await db.execute(select(Subject).where(Subject.investigation_id == investigation_id))).scalars().all()
        if subject_ids:
            subs = [x for x in subs if x.id in subject_ids]
        job_ids: list[str] = []
        for sub in subs:
            requested = module_keys or PLAN.get(sub.type, [])
            modules = [m for m in requested if m in REGISTRY
                       and (sub.type in REGISTRY[m].subject_types or not REGISTRY[m].subject_types)]
            for mk in modules:
                j = Job(investigation_id=investigation_id, subject_id=sub.id, module=mk, status="queued")
                db.add(j)
                await db.flush()
                job_ids.append(j.id)
        inv.status = "running"
        await db.commit()

    sem = asyncio.Semaphore(s.MAX_CONCURRENT_COLLECTORS)
    await asyncio.gather(*[_run_job(sem, j) for j in job_ids])

    async with SessionLocal() as db:
        await correlation.correlate_investigation(db, investigation_id)
        inv = await db.get(Investigation, investigation_id)
        if inv:
            errs = (await db.execute(select(Job).where(Job.investigation_id == investigation_id,
                                                        Job.status == "error"))).scalars().all()
            inv.status = "error" if errs and len(errs) == len(job_ids) else "completed"
            await db.commit()
    return job_ids
