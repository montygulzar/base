"""Webhook notifier — posts a summary of the investigation to a
Slack / Discord / generic JSON webhook URL. Config via WEBHOOK_URL or a
per-subject URL passed as the subject value.
"""
from __future__ import annotations
import httpx
from sqlalchemy import select
from ..config import get_settings
from ..db import SessionLocal
from ..models import Investigation, Entity, Finding as FM
from .base import Module, Finding, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    s = get_settings()
    out = CollectionResult()
    url = (subject or "").strip() or getattr(s, "WEBHOOK_URL", "") or ""
    if not url.startswith(("http://", "https://")):
        out.findings.append(Finding("webhook", "source_unavailable",
                                    {"reason": "no webhook url"}, 0.0))
        return out
    async with SessionLocal() as db:
        inv = await db.get(Investigation, ctx.investigation_id)
        ents = (await db.execute(select(Entity).where(Entity.investigation_id == ctx.investigation_id))).scalars().all()
        finds = (await db.execute(select(FM).where(FM.investigation_id == ctx.investigation_id))).scalars().all()
    if not inv:
        return out
    from collections import Counter
    etypes = Counter(e.type for e in ents)
    modules = Counter(f.module for f in finds)
    text = (f"*base investigation* `{inv.name}` — "
            f"{len(ents)} entities, {len(finds)} findings from "
            f"{len(modules)} modules.")
    # Both Slack & Discord accept `content` or `text`
    payload = {"text": text, "content": text,
               "attachments": [{"fields": [
                   {"title": "entity types", "value": ", ".join(f"{k}:{v}" for k, v in etypes.most_common(10)), "short": False},
                   {"title": "modules", "value": ", ".join(f"{k}:{v}" for k, v in modules.most_common(10)), "short": False},
               ]}]}
    async with httpx.AsyncClient() as c:
        try:
            r = await c.post(url, json=payload, timeout=15)
            out.findings.append(Finding("webhook", "post",
                                        {"status": r.status_code, "url_host": url.split("/")[2]}, 0.9))
        except Exception as e:
            out.findings.append(Finding("webhook", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="webhook",
    name="Webhook notifier",
    subject_types=["url", "domain", "ip", "email", "username", "company",
                   "media", "document", "phone"],
    description="Posts an investigation summary to a webhook (Slack / Discord / JSON).",
    run=run,
))
