"""dnstwist-style typosquat detector.

Generates character-swap / keyboard / insertion / omission / repetition
/ homoglyph / replacement / bitsquatting variants, checks which resolve,
and flags live typosquats. No external services required.
"""
from __future__ import annotations
import asyncio
import string
from itertools import product
import dns.asyncresolver
import tldextract
from ..utils.validators import is_domain, normalise_domain
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register

RESOLVER = dns.asyncresolver.Resolver()
RESOLVER.lifetime = 4.0

# minimal keyboard-adjacency map (qwerty)
NEIGHBORS = {
    "q":"was","w":"qeads","e":"wrsd","r":"etdf","t":"ryfg","y":"tugh","u":"yihj","i":"uojk","o":"ipkl","p":"ol",
    "a":"qwsz","s":"awedxz","d":"serfcx","f":"drtgvc","g":"ftyhbv","h":"gyujnb","j":"huiknm","k":"jiolm",
    "l":"kop","z":"asx","x":"zdc","c":"xdfv","v":"cfgb","b":"vghn","n":"bhjm","m":"njk",
}
HOMOGLYPH = {
    "a":["4","à","á"], "e":["3","é","ë"], "i":["1","l","í"], "o":["0","ó","ö"],
    "l":["1","i"], "s":["5","$","ś"], "g":["q","9"], "c":["ç"], "n":["ñ"],
}


def _variants(label: str) -> set[str]:
    out: set[str] = set()
    if len(label) < 2:
        return out
    # char omission
    for i in range(len(label)):
        out.add(label[:i] + label[i+1:])
    # char repetition
    for i in range(len(label)):
        out.add(label[:i] + label[i] + label[i] + label[i+1:])
    # char swap
    for i in range(len(label) - 1):
        out.add(label[:i] + label[i+1] + label[i] + label[i+2:])
    # keyboard neighbor replacement
    for i, ch in enumerate(label.lower()):
        for n in NEIGHBORS.get(ch, ""):
            out.add(label[:i] + n + label[i+1:])
    # homoglyph
    for i, ch in enumerate(label.lower()):
        for g in HOMOGLYPH.get(ch, []):
            out.add(label[:i] + g + label[i+1:])
    # insertion (digits only, keeps the set bounded)
    for i in range(len(label) + 1):
        for d in string.digits:
            out.add(label[:i] + d + label[i:])
    # bit-squatting: flip one bit per char
    for i, ch in enumerate(label.lower()):
        code = ord(ch)
        for b in range(7):
            flipped = chr(code ^ (1 << b))
            if flipped.isalnum():
                out.add(label[:i] + flipped + label[i+1:])
    out.discard(label)
    return out


async def _resolves(host: str) -> list[str]:
    try:
        a = await RESOLVER.resolve(host, "A")
        return [r.to_text() for r in a]
    except Exception:
        return []


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    d = normalise_domain(subject)
    if not is_domain(d):
        out.findings.append(Finding("typosquat", "invalid_input", {"input": subject}, 0.1))
        return out
    ex = tldextract.extract(d)
    if not ex.domain or not ex.suffix:
        out.findings.append(Finding("typosquat", "invalid_input", {"input": subject}, 0.1))
        return out
    root_label = ex.domain
    suffix = ex.suffix

    variants = _variants(root_label)
    checked = sorted({f"{v}.{suffix}" for v in variants})[:400]  # cap
    out.entities.append(Entity("domain", d, {}, 0.95))
    out.findings.append(Finding("typosquat", "candidates",
                                {"generated": len(checked), "sample": checked[:50]}, 0.8))

    sem = asyncio.Semaphore(32)
    async def check(h):
        async with sem:
            ips = await _resolves(h)
            return h, ips

    results = await asyncio.gather(*[check(h) for h in checked])
    live = [(h, ips) for h, ips in results if ips]
    out.findings.append(Finding("typosquat", "live",
                                {"count": len(live), "live": [{"host": h, "ips": ips} for h, ips in live]},
                                0.9 if live else 0.3))
    for h, ips in live:
        out.entities.append(Entity("domain", h, {"typosquat_of": d, "ips": ips}, 0.85))
        out.relationships.append(Relationship("domain", h, "domain", d, "typosquat_of",
                                              "typosquat", 0.85, {"ips": ips}))
    return out


register(Module(
    key="typosquat",
    name="Typosquat detector",
    subject_types=["domain"],
    description="dnstwist-style variant generation + DNS check.",
    run=run,
))
