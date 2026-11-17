"""Metagoofil-style public document discovery.

Uses DuckDuckGo's HTML search (no key) with filetype operators to find
public documents indexed for a domain, then downloads a bounded sample
and extracts metadata inline via PyMuPDF / python-docx / openpyxl.

Caps: 25 results per filetype, 10 MB per file, 10 downloads total.
"""
from __future__ import annotations
import asyncio
import os
import re
import tempfile
from urllib.parse import quote_plus, urlparse
import httpx
from ..utils.validators import normalise_domain, is_domain
from ..utils.hashing import sha256_file
from ..utils.ratelimit import gate
from ..config import get_settings
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register

UA = {"user-agent": "Mozilla/5.0 (base-osint/0.1) Gecko/20100101 Firefox/120.0"}
FILETYPES = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv"]
RESULT_RE = re.compile(r'href="(https?://[^"]+)"', re.I)


async def _ddg(c: httpx.AsyncClient, q: str) -> list[str]:
    await gate("ddg")
    try:
        r = await c.post("https://html.duckduckgo.com/html/", data={"q": q},
                         headers={**UA, "content-type": "application/x-www-form-urlencoded"},
                         timeout=15, follow_redirects=True)
        if r.status_code != 200:
            return []
        hits = []
        for m in RESULT_RE.findall(r.text):
            if m.startswith("https://duckduckgo.com/l/"):
                # unwrap tracking redirect
                from urllib.parse import parse_qs, unquote
                q = parse_qs(urlparse(m).query).get("uddg", [""])[0]
                if q:
                    hits.append(unquote(q))
            elif "duckduckgo.com" not in m:
                hits.append(m)
        return hits[:25]
    except Exception:
        return []


async def _download_and_extract(c: httpx.AsyncClient, url: str, limit: int) -> dict:
    try:
        r = await c.get(url, timeout=20, follow_redirects=True)
        if r.status_code != 200:
            return {"url": url, "error": f"status={r.status_code}"}
        body = r.content[:limit]
        if len(r.content) > limit:
            return {"url": url, "error": "oversize", "bytes": len(r.content)}
        suffix = os.path.splitext(urlparse(url).path)[1].lower() or ".bin"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(body)
            path = tmp.name
        sha = sha256_file(path)
        meta: dict = {"url": url, "bytes": len(body), "sha256": sha, "suffix": suffix}
        try:
            if suffix == ".pdf":
                import fitz
                d = fitz.open(path)
                meta["meta"] = dict(d.metadata or {})
                meta["pages"] = d.page_count
                d.close()
            elif suffix == ".docx":
                from docx import Document as D
                dd = D(path)
                cp = dd.core_properties
                meta["meta"] = {"author": cp.author, "title": cp.title, "created": str(cp.created),
                                "last_modified_by": cp.last_modified_by}
            elif suffix in (".xlsx", ".xlsm"):
                from openpyxl import load_workbook
                wb = load_workbook(path, read_only=True)
                p = wb.properties
                meta["meta"] = {"creator": p.creator, "title": p.title, "created": str(p.created),
                                "last_modified_by": p.lastModifiedBy}
                wb.close()
        except Exception as e:
            meta["extract_error"] = str(e)
        try:
            os.unlink(path)
        except Exception:
            pass
        return meta
    except Exception as e:
        return {"url": url, "error": str(e)}


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    s = get_settings()
    out = CollectionResult()
    d = normalise_domain(subject)
    if not is_domain(d):
        out.findings.append(Finding("metagoofil", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("domain", d, {}, 0.9))

    all_hits: dict[str, list[str]] = {}
    async with httpx.AsyncClient(headers=UA) as c:
        for ft in FILETYPES:
            hits = await _ddg(c, f"site:{d} filetype:{ft}")
            all_hits[ft] = hits

        flat = []
        for ft, hits in all_hits.items():
            for u in hits:
                flat.append((ft, u))

        out.findings.append(Finding("duckduckgo", "doc_search",
                                    {"total": len(flat), "per_type": {k: len(v) for k, v in all_hits.items()}}, 0.85))

        downloaded = []
        for ft, u in flat[:10]:
            meta = await _download_and_extract(c, u, 10 * 1024 * 1024)
            meta["filetype"] = ft
            downloaded.append(meta)
            if "sha256" in meta:
                out.entities.append(Entity("file", meta["sha256"],
                                           {"url": u, "filetype": ft}, 0.75))
                out.relationships.append(Relationship("domain", d, "file", meta["sha256"],
                                                      "publishes", "metagoofil", 0.8))
                authors = ((meta.get("meta") or {}).get("author")
                           or (meta.get("meta") or {}).get("creator")
                           or (meta.get("meta") or {}).get("last_modified_by"))
                if authors:
                    out.entities.append(Entity("username", str(authors)[:64],
                                               {"source_doc": meta["sha256"]}, 0.6))
                    out.relationships.append(Relationship("file", meta["sha256"], "username", str(authors)[:64],
                                                          "authored_by", "doc_metadata", 0.7))

        out.findings.append(Finding("metagoofil", "downloaded",
                                    {"count": len(downloaded), "docs": downloaded}, 0.85))

    return out


register(Module(
    key="metagoofil",
    name="Public document discovery",
    subject_types=["domain"],
    description="DuckDuckGo filetype search + inline metadata extraction.",
    run=run,
))
