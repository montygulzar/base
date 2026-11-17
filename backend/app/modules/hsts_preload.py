"""HSTS preload-list membership check.

Downloads Chromium's canonical HSTS preload JSON (~10MB) once per
process, caches it, and reports whether the subject domain (or any
parent) is on the preload list.
"""
from __future__ import annotations
import httpx
from ..utils.validators import is_domain, normalise_domain
from .base import Module, Finding, Entity, CollectionResult, RunContext, register

URL = "https://chromium.googlesource.com/chromium/src/+/main/net/http/transport_security_state_static.json?format=TEXT"
_cache: set[str] | None = None


async def _load(c: httpx.AsyncClient) -> set[str]:
    global _cache
    if _cache is not None:
        return _cache
    try:
        import base64, json, re
        r = await c.get(URL, timeout=40)
        if r.status_code != 200:
            _cache = set()
            return _cache
        raw = base64.b64decode(r.text).decode("utf-8", errors="replace")
        # strip // comments
        raw = re.sub(r"^\s*//.*$", "", raw, flags=re.M)
        try:
            j = json.loads(raw)
        except Exception:
            _cache = set()
            return _cache
        entries = j.get("entries") or []
        _cache = {e.get("name") for e in entries if e.get("name")}
        return _cache
    except Exception:
        _cache = set()
        return _cache


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    d = normalise_domain(subject)
    if not is_domain(d):
        out.findings.append(Finding("hsts_preload", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("domain", d, {}, 0.9))
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        names = await _load(c)
    if not names:
        out.findings.append(Finding("hsts_preload", "source_unavailable",
                                    {"reason": "failed to fetch preload list"}, 0.0))
        return out
    # check parents too
    labels = d.split(".")
    hit = None
    for i in range(len(labels) - 1):
        cand = ".".join(labels[i:])
        if cand in names:
            hit = cand; break
    out.findings.append(Finding("hsts_preload", "lookup",
                                {"domain": d, "listed": hit is not None,
                                 "preload_entry": hit,
                                 "list_size": len(names)},
                                0.95))
    return out


register(Module(
    key="hsts_preload",
    name="HSTS preload-list check",
    subject_types=["domain"],
    description="Chromium HSTS-preload membership (checks parents too).",
    run=run,
))
