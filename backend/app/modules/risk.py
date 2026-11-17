"""Risk scorer.

Rolls up all collected signals into a single 0-100 risk score per
investigation. Components:

- Known-malicious reputation: URLhaus host, OTX pulses, VirusTotal
  stats.malicious > 0, ThreatFox hit.
- Breach exposure: HIBP breach count.
- Exposure surface: Shodan tags, GreyNoise classification 'malicious',
  AbuseIPDB abuseConfidenceScore.
- Supply chain risk: CVEs linked to entities (severity-weighted).
- Hygiene: SPF missing / weak, DMARC missing / p=none.
- Secrets: secrets_scan hits (weighted by severity).

Each contributor is bounded, then combined and clamped.
"""
from __future__ import annotations
from sqlalchemy import select
from ..db import SessionLocal
from ..models import Finding, Entity
from .base import Module, Finding as F, CollectionResult, RunContext, register


WEIGHTS = {
    "malicious_rep":  25,
    "breach":         15,
    "exposure":       15,
    "cves":           15,
    "hygiene":        15,
    "secrets":        15,
}


def _bound(x: float) -> float:
    return max(0.0, min(1.0, x))


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    async with SessionLocal() as db:
        finds = (await db.execute(
            select(Finding).where(Finding.investigation_id == ctx.investigation_id)
        )).scalars().all()
        ents = (await db.execute(
            select(Entity).where(Entity.investigation_id == ctx.investigation_id)
        )).scalars().all()

    components: dict[str, dict] = {}

    # malicious reputation
    mal = 0
    mal_evidence = []
    for f in finds:
        d = f.data or {}
        if f.source == "urlhaus" and f.kind in ("host", "url") and d.get("query_status") == "ok":
            mal += 1; mal_evidence.append("urlhaus")
        if f.source == "virustotal" and f.kind == "domain":
            attr = (d.get("attributes") or {}) if "attributes" in d else d
            stats = attr.get("last_analysis_stats") or {}
            if (stats.get("malicious") or 0) > 0:
                mal += stats.get("malicious", 0); mal_evidence.append(f"vt_malicious={stats.get('malicious')}")
        if f.source == "threatfox" and f.kind == "ioc" and d.get("query_status") == "ok":
            mal += 1; mal_evidence.append("threatfox")
        if f.source == "otx" and d.get("pulse_info"):
            pulses = (d.get("pulse_info") or {}).get("count") or 0
            if pulses > 0:
                mal += min(pulses, 5); mal_evidence.append(f"otx_pulses={pulses}")
    components["malicious_rep"] = {"score": _bound(mal / 5.0), "evidence": mal_evidence[:8]}

    # breach
    breaches = 0
    for f in finds:
        if f.source == "hibp" and f.kind == "breaches":
            breaches += (f.data or {}).get("count", 0) or 0
    components["breach"] = {"score": _bound(breaches / 3.0), "evidence": {"count": breaches}}

    # exposure
    exposure = 0
    evid_exp = []
    for f in finds:
        d = f.data or {}
        if f.source == "greynoise" and d.get("classification") == "malicious":
            exposure += 1; evid_exp.append("gn_malicious")
        if f.source == "abuseipdb":
            score = ((d.get("data") or d) or {}).get("abuseConfidenceScore") or 0
            if score >= 50:
                exposure += 1; evid_exp.append(f"abuseipdb={score}")
        if f.source == "shodan" and f.kind == "host":
            vulns = d.get("vulns") or []
            exposure += min(len(vulns), 5); evid_exp.append(f"shodan_vulns={len(vulns)}")
    components["exposure"] = {"score": _bound(exposure / 5.0), "evidence": evid_exp[:8]}

    # cves
    cves = [e for e in ents if e.type == "cve"]
    components["cves"] = {"score": _bound(len(cves) / 5.0),
                          "evidence": {"count": len(cves)}}

    # hygiene (SPF/DMARC)
    hyg = 0; evid_h = []
    for f in finds:
        if f.source == "dns_auth" and f.kind in ("spf_missing", "dmarc_missing"):
            hyg += 1; evid_h.append(f.kind)
        if f.source == "dns_auth" and f.kind == "dmarc":
            if (f.data or {}).get("policy") == "none":
                hyg += 1; evid_h.append("dmarc_p_none")
        if f.source == "dns_auth" and f.kind == "spf":
            for p in (f.data or {}).get("parsed", []):
                if p.get("posture") in ("insecure_allow_all", "missing_all", "neutral"):
                    hyg += 1; evid_h.append(f"spf_{p.get('posture')}")
    components["hygiene"] = {"score": _bound(hyg / 3.0), "evidence": evid_h[:8]}

    # secrets
    sev_counts = {}
    for f in finds:
        if f.source == "secrets_scan" and f.kind == "summary":
            sev_counts = (f.data or {}).get("severity_counts") or {}
            break
    raw = sev_counts.get("critical", 0) * 3 + sev_counts.get("high", 0) * 2 + sev_counts.get("medium", 0) + sev_counts.get("low", 0) * 0.5
    components["secrets"] = {"score": _bound(raw / 5.0), "evidence": sev_counts}

    total = sum(components[k]["score"] * WEIGHTS[k] for k in WEIGHTS)
    verdict = ("critical" if total >= 75 else "high" if total >= 55
               else "elevated" if total >= 35 else "informational")
    out.findings.append(F("risk", "score",
                          {"score": round(total, 1), "verdict": verdict,
                           "components": {k: {"weight": WEIGHTS[k], **components[k]} for k in WEIGHTS}},
                          0.9))
    return out


register(Module(
    key="risk",
    name="Risk scorer",
    subject_types=["domain", "ip", "url", "email", "username", "company",
                   "media", "document", "phone"],
    description="Composite 0–100 risk score from existing findings.",
    run=run,
))
