"""HIBP paste feed — keyless until HIBP tightened, now key required.
This module uses the free, no-key range-password endpoint only for
k-anonymity password lookups — not applicable here. For paste checks
HIBP requires a key. Emit source_unavailable when no key is set.
"""
from __future__ import annotations
import httpx
from ..utils.validators import is_email
from ..config import get_settings
from .base import Module, Finding, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    s = get_settings()
    out = CollectionResult()
    v = (subject or "").strip().lower()
    if not is_email(v):
        out.findings.append(Finding("hibp_pastes", "invalid_input", {"input": subject}, 0.1))
        return out
    if not s.HIBP_API_KEY:
        out.findings.append(Finding("hibp_pastes", "source_unavailable",
                                    {"reason": "HIBP paste endpoint requires api key"}, 0.0))
        return out
    async with httpx.AsyncClient() as c:
        try:
            r = await c.get(f"https://haveibeenpwned.com/api/v3/pasteaccount/{v}",
                            headers={"hibp-api-key": s.HIBP_API_KEY,
                                     "user-agent": "base-osint"}, timeout=15)
            if r.status_code == 200:
                out.findings.append(Finding("hibp_pastes", "pastes",
                                            {"count": len(r.json()), "pastes": r.json()}, 0.9))
            elif r.status_code == 404:
                out.findings.append(Finding("hibp_pastes", "pastes", {"count": 0}, 0.95))
            else:
                out.findings.append(Finding("hibp_pastes", "http_error",
                                            {"status": r.status_code}, 0.1))
        except Exception as e:
            out.findings.append(Finding("hibp_pastes", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="hibp_pastes",
    name="HIBP pastes",
    subject_types=["email"],
    description="Have I Been Pwned paste exposure (needs HIBP_API_KEY).",
    run=run,
))
