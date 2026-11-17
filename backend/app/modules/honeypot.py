"""Honeypot / sinkhole classifier.

Scans the investigation's findings for signals that an IP is a honeypot,
sinkhole, or benign scanner — GreyNoise `classification`, AbuseIPDB
`isPublicScanner` / `usage_type`, Shodan `tags` containing "honeypot".
Emits an `honeypot_signal` finding per matching IP.
"""
from __future__ import annotations
from sqlalchemy import select
from ..db import SessionLocal
from ..models import Finding, Entity
from .base import Module, Finding as F, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    async with SessionLocal() as db:
        finds = (await db.execute(
            select(Finding).where(Finding.investigation_id == ctx.investigation_id)
        )).scalars().all()

    # Build signals per IP
    per_ip: dict[str, dict] = {}
    for f in finds:
        d = f.data or {}
        src = f.source
        ip = d.get("ip_address") or d.get("ip") or ""
        # best-effort: some sources nest ip inside 'host' etc.
        if not ip and f.kind == "host" and "ip" in d:
            ip = d["ip"]
        if src == "shodan" and f.kind == "host" and d.get("tags"):
            tags = d["tags"] or []
            if any("honeypot" in str(t).lower() for t in tags):
                per_ip.setdefault(ip or "unknown", {})["shodan_honeypot_tag"] = True
        if src == "greynoise":
            cls = d.get("classification")
            if cls:
                per_ip.setdefault(ip or "unknown", {})["greynoise_classification"] = cls
        if src == "abuseipdb":
            data2 = d.get("data") or d
            usage = data2.get("usageType") or data2.get("usage_type")
            scanner = data2.get("isPublicScanner")
            if scanner:
                per_ip.setdefault(ip or "unknown", {})["abuseipdb_public_scanner"] = True
            if usage:
                per_ip.setdefault(ip or "unknown", {})["abuseipdb_usage"] = usage

    out.findings.append(F("honeypot", "classifier",
                          {"ips_examined": len(per_ip),
                           "signals": per_ip}, 0.85 if per_ip else 0.3))
    for ip, sigs in per_ip.items():
        if ip and ip != "unknown":
            out.entities.append(
                __import__("app.modules.base", fromlist=["Entity"]).Entity(
                    "ip", ip, {"honeypot_signals": sigs}, 0.8))
    return out


register(Module(
    key="honeypot",
    name="Honeypot / scanner classifier",
    subject_types=["domain", "ip", "url", "email", "company", "username",
                   "media", "document", "phone"],
    description="Derives honeypot/scanner signals from existing findings.",
    run=run,
))
