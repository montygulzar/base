"""Viral cascade — self-propagating investigation.

Seed a subject → run the plan → for every newly discovered entity that
isn't already a subject, compute its proximity to the root (BFS over
confidence-weighted edges, decayed per hop), promote the ones above a
threshold into new subjects, run the plan on them, repeat up to
max_hops. Stop when no new above-threshold entities appear.

Each entity carries, in its `attributes` dict:
    hop             : int  — depth from the original seed (0 = seed)
    root_proximity  : 0..1 — decayed-product of edge confidences along
                      the strongest path back to any seed entity
    root_subjects   : list[str] — seed subject ids whose chain reached it
"""
from __future__ import annotations
import asyncio
import logging
from collections import defaultdict
from sqlalchemy import select
from .db import SessionLocal
from .models import Investigation, Subject, Entity, Relationship, AuditLog
from .orchestrator import plan_and_run
from . import correlation

log = logging.getLogger("cascade")

# Entity types we re-promote to subjects when they're discovered.
ELIGIBLE = {"domain", "ip", "email", "username", "url",
            "discord", "btc", "eth", "phone", "company"}

# Per-hop decay. 0.7^3 = 0.343 — three hops still useful, fifth starts dying.
HOP_DECAY = 0.7


def _proximity_bfs(entities, relationships, root_ids):
    """BFS from the root set, taking the max product of (decay × edge-conf).
    Treats the graph as undirected for pivot reach."""
    adj = defaultdict(list)
    for r in relationships:
        adj[r.src_id].append((r.dst_id, r.confidence))
        adj[r.dst_id].append((r.src_id, r.confidence))
    prox = {rid: 1.0 for rid in root_ids}
    frontier = set(root_ids)
    while frontier:
        nxt = set()
        for curr in frontier:
            base = prox[curr]
            for n, c in adj.get(curr, []):
                score = base * HOP_DECAY * c
                if score > prox.get(n, 0):
                    prox[n] = score
                    nxt.add(n)
        frontier = nxt
    return prox


async def _snapshot(db, inv_id):
    ents = (await db.execute(select(Entity).where(Entity.investigation_id == inv_id))).scalars().all()
    rels = (await db.execute(select(Relationship).where(Relationship.investigation_id == inv_id))).scalars().all()
    subs = (await db.execute(select(Subject).where(Subject.investigation_id == inv_id))).scalars().all()
    return ents, rels, subs


async def _seed_root_entities(db, inv_id):
    """Find or create the Entity rows that match the original Subjects, mark
    them hop=0 / proximity=1, and return their ids."""
    subs = (await db.execute(select(Subject).where(Subject.investigation_id == inv_id))).scalars().all()
    root_ids = []
    for s in subs:
        e = (await db.execute(select(Entity).where(
            Entity.investigation_id == inv_id,
            Entity.type == s.type, Entity.value == s.value,
        ))).scalar_one_or_none()
        if not e:
            e = Entity(investigation_id=inv_id, type=s.type, value=s.value,
                       attributes={}, confidence=0.95)
            db.add(e); await db.flush()
        a = dict(e.attributes or {})
        a["hop"] = 0
        a["root_proximity"] = 1.0
        a["is_root"] = True
        rs = set(a.get("root_subjects") or [])
        rs.add(s.id)
        a["root_subjects"] = sorted(rs)
        e.attributes = a
        root_ids.append(e.id)
    await db.commit()
    return root_ids


async def run_cascade(inv_id: str, max_hops: int = 3,
                     min_proximity: float = 0.15,
                     modules_override: list[str] | None = None,
                     user_id: str | None = None) -> dict:
    """Entry point. Returns a summary."""
    max_hops = max(1, min(max_hops, 6))
    min_proximity = max(0.0, min(min_proximity, 1.0))
    log.info("cascade start inv=%s max_hops=%d min_prox=%.2f", inv_id, max_hops, min_proximity)

    async with SessionLocal() as db:
        db.add(AuditLog(user_id=user_id, action="cascade.start", target=inv_id,
                        detail={"max_hops": max_hops, "min_proximity": min_proximity}))
        await db.commit()

    # Phase 0: run the default plan on the current subjects.
    await plan_and_run(inv_id, modules_override, None)

    async with SessionLocal() as db:
        root_ids = await _seed_root_entities(db, inv_id)

    summary = {
        "inv_id": inv_id,
        "max_hops": max_hops,
        "min_proximity": min_proximity,
        "hops_completed": 0,
        "hops": [],
    }

    for hop in range(1, max_hops + 1):
        async with SessionLocal() as db:
            ents, rels, subs = await _snapshot(db, inv_id)
            subject_keys = {(s.type, s.value) for s in subs}
            prox = _proximity_bfs(ents, rels, root_ids)

            # Candidates: entities not yet promoted, eligible type, above threshold.
            cands = []
            for e in ents:
                if e.type not in ELIGIBLE:
                    continue
                if (e.type, e.value) in subject_keys:
                    continue
                score = prox.get(e.id, 0.0)
                if score < min_proximity:
                    continue
                cands.append((e, score))

            # Rank by proximity desc so the strongest links go first.
            cands.sort(key=lambda t: t[1], reverse=True)

            # Promote them to subjects and tag the entity with hop + proximity.
            new_subject_ids = []
            promoted = []
            for e, score in cands:
                a = dict(e.attributes or {})
                a["hop"] = hop
                a["root_proximity"] = round(score, 4)
                # Find which root(s) the chain reached through
                root_subs = set()
                for r in root_ids:
                    if prox.get(r, 0) > 0 and (prox.get(e.id, 0) > 0):
                        # best-effort: all roots reachable in BFS scope
                        root_subs.add(r)
                a["root_entity_ids"] = sorted(root_subs)
                e.attributes = a

                sub = Subject(investigation_id=inv_id, type=e.type, value=e.value,
                              note=f"cascade hop={hop} prox={score:.3f}")
                db.add(sub); await db.flush()
                new_subject_ids.append(sub.id)
                promoted.append({"id": e.id, "type": e.type, "value": e.value,
                                 "hop": hop, "proximity": round(score, 4)})
            await db.commit()

        if not new_subject_ids:
            log.info("cascade hop %d: no new above-threshold entities, stopping", hop)
            summary["hops"].append({"hop": hop, "promoted": 0, "entities": []})
            break

        log.info("cascade hop %d: promoted %d entities, running plan", hop, len(new_subject_ids))
        await plan_and_run(inv_id, modules_override, new_subject_ids)
        summary["hops_completed"] = hop
        summary["hops"].append({
            "hop": hop,
            "promoted": len(new_subject_ids),
            "entities": promoted[:50],  # cap for response size
        })

    # Final correlation pass on the fully-expanded graph.
    async with SessionLocal() as db:
        await correlation.correlate_investigation(db, inv_id)
        # Post-hoc: recompute proximity across the final graph so all entities
        # (including ones discovered on later hops) carry their proximity score.
        ents, rels, _ = await _snapshot(db, inv_id)
        final_prox = _proximity_bfs(ents, rels, root_ids)
        for e in ents:
            a = dict(e.attributes or {})
            score = final_prox.get(e.id, 0.0)
            if score > 0:
                a.setdefault("hop", a.get("hop", 999))
                a["root_proximity"] = round(score, 4)
                e.attributes = a
        await db.commit()
        db.add(AuditLog(user_id=user_id, action="cascade.complete", target=inv_id,
                        detail={"hops_completed": summary["hops_completed"]}))
        await db.commit()

    log.info("cascade done inv=%s hops=%d", inv_id, summary["hops_completed"])
    return summary
