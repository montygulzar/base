"""ASN → announced prefixes via RIPEstat (keyless).

Input: an ASN as 'AS12345' or '12345', or any IP (looked up to ASN first).
Emits each /xx prefix as a finding and relates the ASN entity.
"""
from __future__ import annotations
import httpx
from ..utils.validators import is_ip
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip().upper()
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        asn = None
        if v.startswith("AS") and v[2:].isdigit():
            asn = v
        elif v.isdigit():
            asn = "AS" + v
        elif is_ip(v):
            # resolve IP → origin ASN via RIPEstat
            try:
                r = await c.get("https://stat.ripe.net/data/network-info/data.json",
                                params={"resource": v}, timeout=15)
                if r.status_code == 200:
                    asns = ((r.json() or {}).get("data") or {}).get("asns") or []
                    if asns:
                        asn = f"AS{asns[0]}"
            except Exception:
                pass
        if not asn:
            out.findings.append(Finding("asn_prefixes", "invalid_input", {"input": subject}, 0.1))
            return out

        out.entities.append(Entity("asn", asn, {}, 0.9))
        try:
            r = await c.get("https://stat.ripe.net/data/announced-prefixes/data.json",
                            params={"resource": asn[2:]}, timeout=25)
            if r.status_code == 200:
                prefixes = ((r.json() or {}).get("data") or {}).get("prefixes") or []
                out.findings.append(Finding("ripestat", "announced_prefixes",
                                            {"asn": asn, "count": len(prefixes),
                                             "prefixes": [p.get("prefix") for p in prefixes[:500]]},
                                            0.9))
                for p in prefixes[:500]:
                    pref = p.get("prefix")
                    if pref:
                        out.entities.append(Entity("ip", pref,  # treat prefix as ip entity for easy correlation
                                                   {"prefix": True, "asn": asn}, 0.7))
                        out.relationships.append(Relationship("ip", pref, "asn", asn,
                                                              "announced_by", "ripestat", 0.9))
            else:
                out.findings.append(Finding("ripestat", "http_error",
                                            {"status": r.status_code}, 0.1))
        except Exception as e:
            out.findings.append(Finding("ripestat", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="asn_prefixes",
    name="ASN announced prefixes",
    subject_types=["ip"],
    description="RIPEstat announced-prefixes for an ASN (or origin ASN of an IP).",
    run=run,
))
