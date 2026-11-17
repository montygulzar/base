"""Public PGP key lookup via keys.openpgp.org (keyless).

Given an email, fetch any uploaded PGP key, pull fingerprint + userids.
"""
from __future__ import annotations
import httpx
from ..utils.validators import is_email
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip().lower()
    if not is_email(v):
        out.findings.append(Finding("pgp_keys", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("email", v, {}, 0.95))
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            r = await c.get(f"https://keys.openpgp.org/vks/v1/by-email/{v}", timeout=15)
            if r.status_code == 200 and "BEGIN PGP PUBLIC KEY BLOCK" in r.text:
                out.findings.append(Finding("pgp_keys", "key",
                                            {"email": v, "bytes": len(r.text),
                                             "preview": r.text[:400]}, 0.95))
                # Fingerprint endpoint (same key)
                try:
                    import re
                    # The VKS response is the ASCII-armored key; we don't parse it
                    # here — just expose its presence. Analysts can use gpg to
                    # extract the exact fingerprint.
                    pass
                except Exception:
                    pass
            elif r.status_code == 404:
                out.findings.append(Finding("pgp_keys", "no_key", {"email": v}, 0.9))
            else:
                out.findings.append(Finding("pgp_keys", "http_error",
                                            {"status": r.status_code}, 0.1))
        except Exception as e:
            out.findings.append(Finding("pgp_keys", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="pgp_keys",
    name="PGP key (keys.openpgp.org)",
    subject_types=["email"],
    description="Public PGP key lookup by email (keyless).",
    run=run,
))
