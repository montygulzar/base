"""Cross-module correlation.

Looks at all entities and findings in an investigation and adds second-order
relationships: shared ASN, shared registrar, shared cert subject, shared
hosting IP, shared email domain, breach-in-common, CVE-in-common.
"""
from __future__ import annotations
from collections import defaultdict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from .models import Entity, Relationship, Finding


async def _rel_exists(db: AsyncSession, inv_id: str, src: str, dst: str, type_: str) -> bool:
    q = select(Relationship).where(
        Relationship.investigation_id == inv_id,
        Relationship.src_id == src, Relationship.dst_id == dst, Relationship.type == type_,
    )
    return (await db.execute(q)).first() is not None


async def correlate_investigation(db: AsyncSession, inv_id: str):
    ents = (await db.execute(select(Entity).where(Entity.investigation_id == inv_id))).scalars().all()
    by_type: dict[str, list[Entity]] = defaultdict(list)
    for e in ents:
        by_type[e.type].append(e)

    # 1. Domains that share an IP (hosted_on cluster)
    ip_to_domains: dict[str, list[Entity]] = defaultdict(list)
    for rel in (await db.execute(select(Relationship).where(
            Relationship.investigation_id == inv_id,
            Relationship.type.in_(["resolves_to", "hosted_on"])))).scalars().all():
        src = await db.get(Entity, rel.src_id)
        dst = await db.get(Entity, rel.dst_id)
        if src and dst and src.type == "domain" and dst.type == "ip":
            ip_to_domains[dst.id].append(src)

    for ip_id, domains in ip_to_domains.items():
        if len(domains) < 2:
            continue
        for i, a in enumerate(domains):
            for b in domains[i+1:]:
                if not await _rel_exists(db, inv_id, a.id, b.id, "co_hosted_with"):
                    db.add(Relationship(investigation_id=inv_id, src_id=a.id, dst_id=b.id,
                                        type="co_hosted_with", source="correlation",
                                        confidence=0.7,
                                        evidence={"shared_ip_entity": ip_id}))

    # 2. Entities that share an ASN
    asn_members: dict[str, list[Entity]] = defaultdict(list)
    for rel in (await db.execute(select(Relationship).where(
            Relationship.investigation_id == inv_id,
            Relationship.type == "announced_by"))).scalars().all():
        src = await db.get(Entity, rel.src_id); dst = await db.get(Entity, rel.dst_id)
        if dst and dst.type == "asn":
            asn_members[dst.id].append(src)
    for asn_id, members in asn_members.items():
        if len(members) < 2:
            continue
        for i, a in enumerate(members):
            for b in members[i+1:]:
                if not await _rel_exists(db, inv_id, a.id, b.id, "same_asn_as"):
                    db.add(Relationship(investigation_id=inv_id, src_id=a.id, dst_id=b.id,
                                        type="same_asn_as", source="correlation", confidence=0.6,
                                        evidence={"asn_entity": asn_id}))

    # 3. Emails sharing a domain
    domain_to_emails: dict[str, list[Entity]] = defaultdict(list)
    for e in by_type.get("email", []):
        dom = e.value.split("@", 1)[-1]
        domain_to_emails[dom].append(e)
    for dom, emails in domain_to_emails.items():
        if len(emails) < 2:
            continue
        for i, a in enumerate(emails):
            for b in emails[i+1:]:
                if not await _rel_exists(db, inv_id, a.id, b.id, "same_mail_domain_as"):
                    db.add(Relationship(investigation_id=inv_id, src_id=a.id, dst_id=b.id,
                                        type="same_mail_domain_as", source="correlation",
                                        confidence=0.65, evidence={"domain": dom}))

    # 4. CVE mentions: any finding referencing CVE-* becomes cve entities and relates to source entity
    import re
    cve_re = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
    findings = (await db.execute(select(Finding).where(Finding.investigation_id == inv_id))).scalars().all()
    for f in findings:
        text = str(f.data)
        for cve in set(m.upper() for m in cve_re.findall(text)):
            q = select(Entity).where(Entity.investigation_id == inv_id,
                                     Entity.type == "cve", Entity.value == cve)
            e = (await db.execute(q)).scalar_one_or_none()
            if not e:
                e = Entity(investigation_id=inv_id, type="cve", value=cve,
                           attributes={"first_seen_in": f.source}, confidence=0.75)
                db.add(e); await db.flush()
            if f.entity_id and not await _rel_exists(db, inv_id, f.entity_id, e.id, "exposed_to"):
                db.add(Relationship(investigation_id=inv_id, src_id=f.entity_id, dst_id=e.id,
                                    type="exposed_to", source=f.source, confidence=0.7,
                                    evidence={"finding_id": f.id}))

    await db.commit()
