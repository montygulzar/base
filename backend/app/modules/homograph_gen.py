"""Homograph defensive generator — for a protected brand, emit the
dangerous look-alikes to proactively register / monitor.

Combines:
- the confusables map (Cyrillic / fullwidth)
- the TLD list from tld_twist
- single-character swap + duplication
"""
from __future__ import annotations
import tldextract
from ..utils.validators import is_domain, normalise_domain
from .base import Module, Finding, Entity, CollectionResult, RunContext, register

CONFUSABLES = {
    "a": ["а", "ɑ"], "e": ["е", "ё"], "o": ["о", "ο", "ө"], "c": ["с"],
    "p": ["р"], "x": ["х", "×"], "y": ["у"], "i": ["і", "ӏ", "1"],
    "l": ["1", "ӏ"], "s": ["ѕ"], "d": ["ԁ"], "n": ["п"],
    "g": ["ɡ", "q"], "h": ["һ"], "k": ["к"], "m": ["м"], "r": ["г"],
    "t": ["т"], "u": ["υ", "ս"], "w": ["ѡ"], "b": ["Ь"],
}


def _variants(label: str) -> list[str]:
    out = set()
    for i, ch in enumerate(label.lower()):
        for g in CONFUSABLES.get(ch, []):
            out.add(label[:i] + g + label[i+1:])
    for i in range(len(label)):
        out.add(label[:i] + label[i] + label[i] + label[i+1:])  # repetition
    return sorted(out)


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    d = normalise_domain(subject)
    if not is_domain(d):
        out.findings.append(Finding("homograph_gen", "invalid_input", {"input": subject}, 0.1))
        return out
    ex = tldextract.extract(d)
    if not ex.domain or not ex.suffix:
        out.findings.append(Finding("homograph_gen", "invalid_input", {"input": subject}, 0.1))
        return out
    variants = _variants(ex.domain)
    out.entities.append(Entity("domain", d, {}, 0.9))
    out.findings.append(Finding("homograph_gen", "variants",
                                {"base": ex.domain, "suffix": ex.suffix,
                                 "count": len(variants),
                                 "candidates": [f"{v}.{ex.suffix}" for v in variants[:200]]},
                                0.85))
    return out


register(Module(
    key="homograph_gen",
    name="Homograph defensive generator",
    subject_types=["domain", "company"],
    description="Generates look-alike brand-domain variants for defensive monitoring.",
    run=run,
))
