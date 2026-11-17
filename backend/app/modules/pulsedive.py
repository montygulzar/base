"""Pulsedive — free community CTI, no key required for basic lookups."""
from __future__ import annotations
import httpx
from ..utils.validators import is_ip, is_domain, is_private_ip
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    if is_ip(v) and is_private_ip(v):
        out.findings.append(Finding("pulsedive", "private_address", {"ip": v}, 1.0))
        return out
    if not (is_ip(v) or is_domain(v) or v.startswith("http")):
        out.findings.append(Finding("pulsedive", "invalid_input", {"input": subject}, 0.1))
        return out
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            r = await c.get("https://pulsedive.com/api/info.php",
                            params={"indicator": v, "pretty": 1}, timeout=20)
            if r.status_code == 200:
                try:
                    j = r.json()
                except Exception:
                    j = {"raw": r.text[:300]}
                out.findings.append(Finding("pulsedive", "info", j, 0.85))
                if is_domain(v):
                    out.entities.append(Entity("domain", v, {}, 0.9))
                elif is_ip(v):
                    out.entities.append(Entity("ip", v, {}, 0.9))
            else:
                out.findings.append(Finding("pulsedive", "http_error",
                                            {"status": r.status_code}, 0.1))
        except Exception as e:
            out.findings.append(Finding("pulsedive", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="pulsedive",
    name="Pulsedive",
    subject_types=["ip", "domain", "url"],
    description="Pulsedive community CTI lookup (keyless).",
    run=run,
))
