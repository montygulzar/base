"""Wayback Machine integration.

- availability check
- CDX index of unique archived URLs for the domain
- extracts JS endpoints and interesting file types
"""
from __future__ import annotations
import re
import httpx
from collections import Counter
from urllib.parse import urlparse
from ..utils.validators import is_domain, normalise_domain
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


UA = {"user-agent": "Mozilla/5.0 base-osint/0.1"}
INTERESTING_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                   ".zip", ".tar", ".gz", ".txt", ".csv", ".json", ".xml",
                   ".bak", ".sql", ".env", ".config", ".yaml", ".yml", ".ini"}


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    d = normalise_domain(subject)
    if not is_domain(d):
        out.findings.append(Finding("wayback", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("domain", d, {}, 0.9))

    async with httpx.AsyncClient(headers=UA) as c:
        # 1. Availability
        try:
            r = await c.get(f"https://archive.org/wayback/available?url={d}", timeout=15)
            if r.status_code == 200:
                out.findings.append(Finding("wayback", "availability", r.json(), 0.9))
        except Exception as e:
            out.findings.append(Finding("wayback", "error", {"error": str(e)}, 0.1))

        # 2. CDX index
        try:
            r = await c.get(
                "https://web.archive.org/cdx/search/cdx",
                params={"url": f"{d}/*", "output": "json", "fl": "timestamp,original,statuscode,mimetype",
                        "collapse": "urlkey", "limit": "10000"},
                timeout=30,
            )
            if r.status_code == 200:
                rows = r.json()
                if rows and len(rows) > 1:
                    urls = []
                    paths = Counter()
                    docs = []
                    for ts, url, status, mime in rows[1:]:
                        urls.append(url)
                        p = urlparse(url).path
                        paths[p] += 1
                        low = (url or "").lower()
                        if any(low.endswith(ext) for ext in INTERESTING_EXT):
                            docs.append({"url": url, "mime": mime, "status": status, "ts": ts})
                    out.findings.append(Finding("wayback", "cdx_index",
                                                {"total_rows": len(rows) - 1,
                                                 "unique_urls": len(set(urls)),
                                                 "top_paths": paths.most_common(50)}, 0.9))
                    out.findings.append(Finding("wayback", "archived_documents",
                                                {"count": len(docs), "documents": docs[:200]}, 0.85))
                    for doc in docs[:200]:
                        out.entities.append(Entity("url", doc["url"], {"archived": True, "mime": doc["mime"]}, 0.7))
                        out.relationships.append(Relationship("domain", d, "url", doc["url"],
                                                              "archived_doc", "wayback", 0.75))
                else:
                    out.findings.append(Finding("wayback", "cdx_index", {"total_rows": 0}, 0.3))
        except Exception as e:
            out.findings.append(Finding("wayback", "error", {"error": str(e)}, 0.1))

    return out


register(Module(
    key="wayback",
    name="Wayback Machine",
    subject_types=["domain", "url"],
    description="archive.org CDX index + archived-document discovery.",
    run=run,
))
