"""Basic Tor .onion address validation.

- v2 is 16 chars (now dead but still in the wild). We reject.
- v3 is 56 chars of base32 + '.onion'. We validate charset and
  checksum length.
"""
from __future__ import annotations
import re
from .base import Module, Finding, Entity, CollectionResult, RunContext, register

V2_RE = re.compile(r"^[a-z2-7]{16}\.onion$", re.I)
V3_RE = re.compile(r"^[a-z2-7]{56}\.onion$", re.I)


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip().lower()
    if not v.endswith(".onion"):
        out.findings.append(Finding("onion_validate", "invalid_input", {"input": subject}, 0.1))
        return out
    version = None
    if V3_RE.match(v):
        version = "v3"
    elif V2_RE.match(v):
        version = "v2_deprecated"
    verdict = "valid" if version == "v3" else "deprecated" if version == "v2_deprecated" else "malformed"
    out.entities.append(Entity("url", f"http://{v}", {"onion": True, "version": version}, 0.8))
    out.findings.append(Finding("onion_validate", "analysis",
                                {"host": v, "version": version, "verdict": verdict,
                                 "length": len(v) - len(".onion")},
                                0.95))
    return out


register(Module(
    key="onion_validate",
    name="Onion validate",
    subject_types=["domain", "url"],
    description="Tor .onion v2/v3 validity check.",
    run=run,
))
