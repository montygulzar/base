"""SPF / DMARC / DKIM record parser (deeper than plain DNS lookup).

- SPF: pulls every `v=spf1` TXT record, parses mechanisms and modifiers.
  Flags +all / softfail / neutral / missing policies as risk indicators.
- DMARC: pulls _dmarc.<domain> TXT, parses tags, flags p=none, aggregates
  rua/ruf destinations as email entities.
- DKIM: brute-forces common selectors (default, google, selector1,
  selector2, k1, m1, mail, s1, s2, s1024, selector) and reports which
  publish a key.
"""
from __future__ import annotations
import asyncio
import re
import dns.asyncresolver
from ..utils.validators import is_domain, normalise_domain, is_email
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register

RESOLVER = dns.asyncresolver.Resolver()
RESOLVER.lifetime = 6.0
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "m1",
                  "mail", "s1", "s2", "s1024", "selector", "dkim", "key1"]


async def _txt(name: str) -> list[str]:
    try:
        a = await RESOLVER.resolve(name, "TXT")
        return [r.to_text().strip('"').replace('" "', '') for r in a]
    except Exception:
        return []


def _parse_spf(record: str) -> dict:
    parts = record.split()
    mechanisms = []
    modifiers = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            modifiers[k.lstrip("+-?~")] = v
        else:
            mechanisms.append(p)
    all_mech = next((m for m in mechanisms if m.endswith("all")), "")
    posture = {
        "+all": "insecure_allow_all",
        "-all": "strict_fail",
        "~all": "soft_fail",
        "?all": "neutral",
        "": "missing_all",
    }.get(all_mech, "unknown")
    return {"mechanisms": mechanisms, "modifiers": modifiers, "all": all_mech, "posture": posture}


def _parse_dmarc(record: str) -> dict:
    tags = {}
    for pair in record.split(";"):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            tags[k.strip()] = v.strip()
    return tags


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    d = normalise_domain(subject.split("@", 1)[-1]) if "@" in (subject or "") else normalise_domain(subject)
    if not is_domain(d):
        out.findings.append(Finding("dns_auth", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("domain", d, {}, 0.9))

    spf_txt, dmarc_txt = await asyncio.gather(_txt(d), _txt(f"_dmarc.{d}"))
    spf = [t for t in spf_txt if t.lower().startswith("v=spf1")]
    dmarc = [t for t in dmarc_txt if t.lower().startswith("v=dmarc1")]

    if spf:
        parsed = [_parse_spf(s) for s in spf]
        out.findings.append(Finding("dns_auth", "spf", {"raw": spf, "parsed": parsed}, 0.95))
    else:
        out.findings.append(Finding("dns_auth", "spf_missing", {"domain": d}, 0.9))

    if dmarc:
        tags = _parse_dmarc(dmarc[0])
        out.findings.append(Finding("dns_auth", "dmarc", {"raw": dmarc[0], "tags": tags,
                                                           "policy": tags.get("p", "none"),
                                                           "spolicy": tags.get("sp")}, 0.95))
        for key in ("rua", "ruf"):
            if tags.get(key):
                for m in re.findall(r"mailto:([^,\s;]+)", tags[key]):
                    if is_email(m):
                        out.entities.append(Entity("email", m.lower(), {"source": f"dmarc_{key}"}, 0.7))
                        out.relationships.append(Relationship("domain", d, "email", m.lower(),
                                                              "reports_to", f"dmarc_{key}", 0.8))
    else:
        out.findings.append(Finding("dns_auth", "dmarc_missing", {"domain": d}, 0.9))

    # DKIM selector brute force (bounded, parallel)
    async def chk(sel: str):
        r = await _txt(f"{sel}._domainkey.{d}")
        return sel, r

    dkim_results = await asyncio.gather(*[chk(s) for s in DKIM_SELECTORS])
    live = {sel: recs for sel, recs in dkim_results if recs}
    out.findings.append(Finding("dns_auth", "dkim_selectors",
                                {"checked": DKIM_SELECTORS, "live": live}, 0.9 if live else 0.3))
    return out


register(Module(
    key="dns_auth",
    name="SPF / DMARC / DKIM",
    subject_types=["domain", "email"],
    description="Deep parse of SPF / DMARC / DKIM with selector enumeration.",
    run=run,
))
