"""Package-ecosystem typosquat check (npm + PyPI).

Given a package name, generate typo-variants and check which ones are
registered. Useful for defending a published package or spotting a
supply-chain lookalike campaign.
"""
from __future__ import annotations
import asyncio
import string
import httpx
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


def _variants(n: str) -> set[str]:
    out: set[str] = set()
    low = n.lower()
    for i in range(len(low)):
        out.add(low[:i] + low[i+1:])                        # omission
        out.add(low[:i] + low[i] + low[i] + low[i+1:])       # repetition
    for i in range(len(low) - 1):
        out.add(low[:i] + low[i+1] + low[i] + low[i+2:])    # swap
    for i in range(len(low) + 1):
        for ch in string.ascii_lowercase + "-_" + string.digits:
            out.add(low[:i] + ch + low[i:])                  # insertion
    out.discard(low)
    return out


async def _npm(c: httpx.AsyncClient, name: str) -> bool:
    try:
        r = await c.get(f"https://registry.npmjs.org/{name}", timeout=10)
        return r.status_code == 200
    except Exception:
        return False


async def _pypi(c: httpx.AsyncClient, name: str) -> bool:
    try:
        r = await c.get(f"https://pypi.org/pypi/{name}/json", timeout=10)
        return r.status_code == 200
    except Exception:
        return False


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip().lower()
    if not v or len(v) < 2:
        out.findings.append(Finding("package_typosquat", "invalid_input", {"input": subject}, 0.1))
        return out
    variants = sorted(_variants(v))[:400]
    sem = asyncio.Semaphore(24)

    async def check_npm(nm):
        async with sem:
            return nm, await _npm(c, nm)

    async def check_pypi(nm):
        async with sem:
            return nm, await _pypi(c, nm)

    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        npm_hits = [nm for nm, ok in await asyncio.gather(*[check_npm(nm) for nm in variants]) if ok]
        pypi_hits = [nm for nm, ok in await asyncio.gather(*[check_pypi(nm) for nm in variants]) if ok]
    out.findings.append(Finding("package_typosquat", "npm",
                                {"input": v, "checked": len(variants),
                                 "live": npm_hits}, 0.9 if npm_hits else 0.5))
    out.findings.append(Finding("package_typosquat", "pypi",
                                {"input": v, "checked": len(variants),
                                 "live": pypi_hits}, 0.9 if pypi_hits else 0.5))
    for nm in npm_hits:
        out.entities.append(Entity("username", f"npm:{nm}", {"typosquat_of": v}, 0.75))
    for nm in pypi_hits:
        out.entities.append(Entity("username", f"pypi:{nm}", {"typosquat_of": v}, 0.75))
    return out


register(Module(
    key="package_typosquat",
    name="Package typosquat (npm + PyPI)",
    subject_types=["username", "company"],
    description="Enumerate typo-variants of a package name against npm and PyPI.",
    run=run,
))
