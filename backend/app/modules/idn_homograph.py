"""IDN / Punycode / homograph detection.

Flags a domain if it uses Punycode (xn--) or contains Cyrillic / Greek /
Armenian / full-width characters that visually mimic ASCII. Decodes
Punycode to the Unicode label and reports the "skeleton" (ASCII look-
alike form) for clustering.
"""
from __future__ import annotations
import unicodedata
from ..utils.validators import is_domain, normalise_domain
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


# Latin look-alikes: a minimal confusables map. Full Unicode confusables
# is enormous; this subset catches the typical phishing homoglyphs.
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "с": "c", "р": "p", "х": "x", "у": "y",  # cyrillic
    "ԁ": "d", "ɡ": "g", "һ": "h", "і": "i", "ј": "j", "ӏ": "l", "ν": "v",
    "ѕ": "s", "ԛ": "q", "ʏ": "y", "κ": "k",
    "α": "a", "ο": "o", "β": "b", "ρ": "p", "τ": "t",  # greek
    "０": "0", "１": "1", "２": "2", "３": "3", "４": "4",                 # fullwidth digits
    "５": "5", "６": "6", "７": "7", "８": "8", "９": "9",
    "ａ": "a", "ｂ": "b", "ｃ": "c", "ｄ": "d",                                # fullwidth letters
}


def skeleton(s: str) -> str:
    return "".join(CONFUSABLES.get(ch, ch) for ch in s).lower()


def script_mix(s: str) -> list[str]:
    scripts = set()
    for ch in s:
        if ch.isalpha():
            try:
                name = unicodedata.name(ch)
                scripts.add(name.split()[0])
            except ValueError:
                pass
    return sorted(scripts)


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    d = normalise_domain(subject)
    if not is_domain(d):
        out.findings.append(Finding("idn_homograph", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("domain", d, {}, 0.9))
    uni = d
    pre_puny = ""
    try:
        if "xn--" in d:
            pre_puny = d.encode("ascii").decode("idna")
            uni = pre_puny
    except Exception:
        pass
    scripts = script_mix(uni)
    sk = skeleton(uni)
    verdict = "ok"
    reasons: list[str] = []
    if pre_puny:
        reasons.append("punycode_detected"); verdict = "idn"
    if len(scripts) > 1 and "LATIN" in scripts:
        reasons.append(f"mixed_scripts:{scripts}"); verdict = "suspicious"
    if sk != uni.lower():
        reasons.append(f"skeleton_differs:{sk}"); verdict = "suspicious"
    out.findings.append(Finding("idn_homograph", "analysis",
                                {"domain": d, "unicode_form": uni,
                                 "punycode_decoded": pre_puny,
                                 "scripts": scripts, "skeleton": sk,
                                 "verdict": verdict, "reasons": reasons},
                                0.95))
    return out


register(Module(
    key="idn_homograph",
    name="IDN homograph detect",
    subject_types=["domain"],
    description="Flags punycode + mixed-script + homoglyph domains.",
    run=run,
))
