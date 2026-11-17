"""Secrets / credential pattern scanner.

Walks the investigation's findings (especially document / crawler
extracts and HTML responses) for well-known credential patterns:
AWS access keys, Google API keys, GitHub tokens, Slack tokens, private
RSA headers, generic 'password=' / 'api_key=' leaks. Emits each match
with surrounding context and a severity hint.
"""
from __future__ import annotations
import re
from sqlalchemy import select
from ..db import SessionLocal
from ..models import Finding
from .base import Module, Finding as F, CollectionResult, RunContext, register


RULES: list[tuple[str, str, str]] = [  # (name, regex, severity)
    ("aws_access_key_id",       r"AKIA[0-9A-Z]{16}",                             "high"),
    ("aws_secret_access_key",   r"(?i)aws(.{0,20})?(secret|private)?(.{0,20})?(key)?(.{0,20})?['\"]?[0-9a-zA-Z/+]{40}['\"]?", "high"),
    ("github_token",            r"gh[pousr]_[A-Za-z0-9]{36,}",                   "high"),
    ("github_oauth",            r"github_pat_[A-Za-z0-9_]{80,}",                 "high"),
    ("slack_token",             r"xox[baprs]-[A-Za-z0-9-]{10,48}",               "high"),
    ("google_api_key",          r"AIza[0-9A-Za-z\-_]{35}",                       "high"),
    ("private_key",             r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----", "critical"),
    ("stripe_live_key",         r"sk_live_[0-9a-zA-Z]{24,}",                     "critical"),
    ("mailgun_api_key",         r"key-[0-9a-zA-Z]{32}",                          "medium"),
    ("heroku_api_key",          r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "low"),
    ("generic_password_eq",     r"(?i)(password|passwd|pwd)\s*[=:]\s*[\"']?[^\s\"'<>{}]{6,}", "medium"),
    ("generic_api_key_eq",      r"(?i)(api[_-]?key|apikey|secret)\s*[=:]\s*[\"']?[A-Za-z0-9/+\-_]{16,}", "medium"),
    ("jwt",                     r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",     "medium"),
]
COMPILED = [(n, re.compile(rx), sev) for n, rx, sev in RULES]


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    async with SessionLocal() as db:
        finds = (await db.execute(
            select(Finding).where(Finding.investigation_id == ctx.investigation_id)
        )).scalars().all()
    hits = []
    for f in finds:
        blob = str(f.data or "")
        for name, rx, sev in COMPILED:
            for m in rx.finditer(blob):
                start = max(0, m.start() - 20)
                end = min(len(blob), m.end() + 20)
                hits.append({
                    "rule": name, "severity": sev,
                    "match_preview": blob[start:end],
                    "finding_id": f.id, "source": f.source, "module": f.module,
                })
                if len(hits) >= 500:
                    break
            if len(hits) >= 500:
                break
        if len(hits) >= 500:
            break
    sev_counts: dict[str, int] = {}
    for h in hits:
        sev_counts[h["severity"]] = sev_counts.get(h["severity"], 0) + 1
    out.findings.append(F("secrets_scan", "summary",
                          {"total_hits": len(hits), "severity_counts": sev_counts}, 0.9))
    out.findings.append(F("secrets_scan", "hits", {"hits": hits[:200]},
                          0.9 if hits else 0.4))
    return out


register(Module(
    key="secrets_scan",
    name="Secrets scanner",
    subject_types=["domain", "ip", "url", "email", "username", "company",
                   "media", "document", "phone"],
    description="Regex-based credential / token leak scan over collected findings.",
    run=run,
))
