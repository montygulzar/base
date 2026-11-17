"""Public document analysis — PDF / DOCX / XLSX metadata and text."""
from __future__ import annotations
import re
from pathlib import Path
import fitz  # pymupdf
from docx import Document as DocxDocument
from openpyxl import load_workbook
from ..utils.hashing import sha256_file
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
URL_RE = re.compile(r"https?://[^\s<>\"']+")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)


def _pdf(path: str) -> tuple[dict, str]:
    doc = fitz.open(path)
    meta = dict(doc.metadata or {})
    meta["page_count"] = doc.page_count
    text = "\n".join(p.get_text() for p in doc)
    doc.close()
    return meta, text


def _docx(path: str) -> tuple[dict, str]:
    d = DocxDocument(path)
    cp = d.core_properties
    meta = {
        "author": cp.author, "title": cp.title, "subject": cp.subject, "keywords": cp.keywords,
        "created": cp.created.isoformat() if cp.created else None,
        "modified": cp.modified.isoformat() if cp.modified else None,
        "last_modified_by": cp.last_modified_by, "revision": cp.revision,
    }
    text = "\n".join(p.text for p in d.paragraphs)
    return meta, text


def _xlsx(path: str) -> tuple[dict, str]:
    wb = load_workbook(path, data_only=True, read_only=True)
    p = wb.properties
    meta = {
        "creator": p.creator, "title": p.title, "subject": p.subject, "description": p.description,
        "created": p.created.isoformat() if p.created else None,
        "modified": p.modified.isoformat() if p.modified else None,
        "last_modified_by": p.lastModifiedBy,
        "sheets": wb.sheetnames,
    }
    # light text sample
    text_parts = []
    for sheet in wb.worksheets[:5]:
        for row in sheet.iter_rows(max_rows=50, values_only=True):
            text_parts.append(" ".join(str(c) for c in row if c is not None))
    wb.close()
    return meta, "\n".join(text_parts)


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    p = Path(subject)
    if not p.exists() or not p.is_file():
        out.findings.append(Finding("documents", "invalid_input", {"path": subject}, 0.1))
        return out

    sha = sha256_file(p)
    out.entities.append(Entity("file", sha, {"name": p.name, "size": p.stat().st_size}, 0.95))
    out.findings.append(Finding("hash", "sha256", {"sha256": sha, "name": p.name}, 1.0))

    suffix = p.suffix.lower()
    try:
        if suffix == ".pdf":
            meta, text = _pdf(str(p))
            src = "pymupdf"
        elif suffix == ".docx":
            meta, text = _docx(str(p))
            src = "docx"
        elif suffix in (".xlsx", ".xlsm"):
            meta, text = _xlsx(str(p))
            src = "openpyxl"
        else:
            out.findings.append(Finding("documents", "unsupported", {"suffix": suffix}, 0.2))
            return out
    except Exception as e:
        out.findings.append(Finding("documents", "error", {"error": str(e)}, 0.1))
        return out

    out.findings.append(Finding(src, "metadata", meta, 0.9))
    text_sample = text[:5000]
    out.findings.append(Finding(src, "text_sample", {"bytes": len(text), "preview": text_sample}, 0.85))

    emails = sorted(set(EMAIL_RE.findall(text)))
    urls = sorted(set(URL_RE.findall(text)))
    domains = sorted({d.lower() for d in DOMAIN_RE.findall(text)})
    out.findings.append(Finding("extract", "indicators",
                                {"emails": emails[:100], "urls": urls[:100], "domains": domains[:200]}, 0.8))

    for e in emails[:100]:
        out.entities.append(Entity("email", e, {"from_file": sha}, 0.7))
        out.relationships.append(Relationship("file", sha, "email", e, "mentions", src, 0.7))
    for u in urls[:100]:
        out.entities.append(Entity("url", u, {"from_file": sha}, 0.7))
        out.relationships.append(Relationship("file", sha, "url", u, "mentions", src, 0.7))
    for d in domains[:200]:
        out.entities.append(Entity("domain", d, {"from_file": sha}, 0.65))
        out.relationships.append(Relationship("file", sha, "domain", d, "mentions", src, 0.7))

    return out


register(Module(
    key="documents",
    name="Document analysis",
    subject_types=["document"],
    description="PDF/DOCX/XLSX metadata + indicator extraction.",
    run=run,
))
