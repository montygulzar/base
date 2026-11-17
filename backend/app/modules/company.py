"""Company / organisation intelligence (deeper).

- SEC EDGAR: resolve company → CIK via /cgi-bin/browse-edgar then pull
  /submissions/CIK{10}.json for filings, SIC code, state, former names.
- Companies House UK: /search/companies and /company/{number} + officers
  (optional COMPANIESHOUSE_API_KEY).
- OpenCorporates (optional key) for broader jurisdiction coverage.
"""
from __future__ import annotations
import re
import httpx
from urllib.parse import quote_plus
from ..config import get_settings
from ..utils.ratelimit import gate
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


UA = {"user-agent": "base-osint/0.1 research@local"}
CIK_RE = re.compile(r"CIK=(\d{10})")


async def _edgar_lookup(c: httpx.AsyncClient, name: str) -> list[str]:
    try:
        r = await c.get(
            f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&company={quote_plus(name)}&type=&dateb=&owner=include&count=20",
            timeout=20, headers=UA,
        )
        if r.status_code != 200:
            return []
        return sorted(set(CIK_RE.findall(r.text)))[:10]
    except Exception:
        return []


async def _edgar_submissions(c: httpx.AsyncClient, cik: str) -> dict:
    try:
        r = await c.get(f"https://data.sec.gov/submissions/CIK{cik}.json",
                        timeout=20, headers=UA)
        if r.status_code == 200:
            j = r.json()
            recent = j.get("filings", {}).get("recent", {})
            filings = []
            if recent:
                forms = recent.get("form", [])
                dates = recent.get("filingDate", [])
                accs = recent.get("accessionNumber", [])
                for i in range(min(25, len(forms))):
                    filings.append({"form": forms[i], "date": dates[i], "accession": accs[i]})
            return {
                "cik": cik, "name": j.get("name"), "sic": j.get("sic"), "sic_description": j.get("sicDescription"),
                "state_of_incorporation": j.get("stateOfIncorporation"),
                "former_names": j.get("formerNames", []),
                "tickers": j.get("tickers", []), "exchanges": j.get("exchanges", []),
                "addresses": j.get("addresses", {}),
                "recent_filings": filings,
            }
    except Exception as e:
        return {"error": str(e)}
    return {}


async def _companies_house_search(c: httpx.AsyncClient, key: str, q: str) -> dict:
    await gate("companieshouse")
    try:
        r = await c.get("https://api.company-information.service.gov.uk/search/companies",
                        params={"q": q}, auth=(key, ""), timeout=20, headers=UA)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        return {"error": str(e)}
    return {}


async def _companies_house_officers(c: httpx.AsyncClient, key: str, num: str) -> dict:
    await gate("companieshouse")
    try:
        r = await c.get(f"https://api.company-information.service.gov.uk/company/{num}/officers",
                        auth=(key, ""), timeout=20, headers=UA)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        return {"error": str(e)}
    return {}


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    s = get_settings()
    out = CollectionResult()
    name = (subject or "").strip()
    if not name:
        out.findings.append(Finding("company", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("org", name, {}, 0.9))

    async with httpx.AsyncClient(headers=UA) as c:
        # 1. SEC EDGAR
        ciks = await _edgar_lookup(c, name)
        out.findings.append(Finding("sec_edgar", "cik_lookup",
                                    {"ciks": ciks, "count": len(ciks)}, 0.85 if ciks else 0.2))
        for cik in ciks:
            data = await _edgar_submissions(c, cik)
            if data and "error" not in data:
                out.findings.append(Finding("sec_edgar", "submissions", data, 0.9))
                real_name = data.get("name")
                if real_name:
                    out.entities.append(Entity("org", real_name, {"cik": cik, "jurisdiction": "US"}, 0.9))
                    out.relationships.append(Relationship("org", name, "org", real_name,
                                                          "candidate_match", "sec_edgar", 0.8))
                for former in data.get("former_names") or []:
                    nm = former.get("name")
                    if nm:
                        out.entities.append(Entity("org", nm, {"status": "former", "cik": cik}, 0.75))
                        out.relationships.append(Relationship("org", real_name or name, "org", nm,
                                                              "formerly_known_as", "sec_edgar", 0.9))
                for tk in data.get("tickers") or []:
                    out.findings.append(Finding("sec_edgar", "ticker", {"ticker": tk, "cik": cik}, 0.9))

        # 2. Companies House UK
        if s.COMPANIESHOUSE_API_KEY:
            srch = await _companies_house_search(c, s.COMPANIESHOUSE_API_KEY, name)
            hits = (srch.get("items") or [])[:15]
            out.findings.append(Finding("companies_house", "search",
                                        {"hits": len(hits), "items": hits}, 0.9 if hits else 0.3))
            for h in hits:
                num = h.get("company_number")
                title = h.get("title") or ""
                if num and title:
                    out.entities.append(Entity("org", title, {"company_number": num, "jurisdiction": "UK"}, 0.85))
                    out.relationships.append(Relationship("org", name, "org", title,
                                                          "candidate_match", "companies_house", 0.75))
                    off = await _companies_house_officers(c, s.COMPANIESHOUSE_API_KEY, num)
                    officers = (off.get("items") or [])[:25]
                    if officers:
                        out.findings.append(Finding("companies_house", "officers",
                                                    {"company": title, "officers": officers}, 0.85))
                        for o in officers:
                            nm = o.get("name") or ""
                            if nm:
                                out.entities.append(Entity("username", nm[:64], {"role": o.get("officer_role"),
                                                                                  "company_number": num}, 0.7))
                                out.relationships.append(Relationship("org", title, "username", nm[:64],
                                                                      "officer_of", "companies_house", 0.85))
        else:
            out.findings.append(Finding("companies_house", "source_unavailable", {"reason": "no api key"}, 0.0))

        # 3. OpenCorporates
        if s.OPENCORPORATES_API_KEY:
            await gate("opencorporates")
            try:
                r = await c.get(
                    f"https://api.opencorporates.com/v0.4/companies/search?q={quote_plus(name)}&api_token={s.OPENCORPORATES_API_KEY}",
                    timeout=20)
                if r.status_code == 200:
                    j = r.json()
                    hits = (j.get("results") or {}).get("companies") or []
                    out.findings.append(Finding("opencorporates", "search",
                                                {"hits": len(hits), "companies": hits[:50]}, 0.85))
                    for h in hits[:50]:
                        co = h.get("company") or {}
                        if co.get("name"):
                            out.entities.append(Entity("org", co["name"],
                                                       {"jurisdiction": co.get("jurisdiction_code"),
                                                        "number": co.get("company_number")}, 0.75))
                            out.relationships.append(Relationship("org", name, "org", co["name"],
                                                                  "candidate_match", "opencorporates", 0.6))
            except Exception as e:
                out.findings.append(Finding("opencorporates", "error", {"error": str(e)}, 0.1))
        else:
            out.findings.append(Finding("opencorporates", "source_unavailable", {"reason": "no api key"}, 0.0))

    return out


register(Module(
    key="company",
    name="Company intelligence",
    subject_types=["company"],
    description="SEC EDGAR submissions + Companies House (UK) + OpenCorporates.",
    run=run,
))
