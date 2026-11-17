"""Integration registry — described declaratively, keyed by provider name.
Each entry: name, configured (bool), description, docs_url, scopes.
`configured` is derived from env at import time.
"""
from __future__ import annotations
from ..config import get_settings

s = get_settings()

REGISTRY: dict[str, dict] = {
    "crt.sh":          {"configured": True,  "scope": ["certificate_transparency"],
                        "description": "crt.sh — Certificate Transparency search (no key).",
                        "docs": "https://crt.sh/"},
    "dns":             {"configured": True,  "scope": ["dns"],
                        "description": "System DNS resolver (dnspython).", "docs": ""},
    "rdap":            {"configured": True,  "scope": ["network_whois"],
                        "description": "RDAP lookups via ARIN endpoints.", "docs": "https://rdap.arin.net"},
    "bgpview":         {"configured": True,  "scope": ["asn", "network"],
                        "description": "bgpview.io ASN/prefix lookups (no key).", "docs": "https://bgpview.docs.apiary.io/"},
    "ripestat":        {"configured": True,  "scope": ["network"],
                        "description": "RIPEstat network-info (no key).", "docs": "https://stat.ripe.net"},
    "sec_edgar":       {"configured": True,  "scope": ["corporate"],
                        "description": "US SEC EDGAR filings search.", "docs": "https://www.sec.gov/edgar"},
    "nvd":             {"configured": True,  "scope": ["cve"],
                        "description": "NIST NVD CVE API (no key).", "docs": "https://nvd.nist.gov/developers"},
    "threatfox":       {"configured": True,  "scope": ["threat_intel"],
                        "description": "abuse.ch ThreatFox IOC API.", "docs": "https://threatfox.abuse.ch"},
    "virustotal":      {"configured": bool(s.VIRUSTOTAL_API_KEY), "scope": ["reputation"],
                        "description": "VirusTotal v3 API.", "docs": "https://developers.virustotal.com/reference"},
    "securitytrails":  {"configured": bool(s.SECURITYTRAILS_API_KEY), "scope": ["passive_dns"],
                        "description": "SecurityTrails passive DNS.", "docs": "https://docs.securitytrails.com"},
    "shodan":          {"configured": bool(s.SHODAN_API_KEY), "scope": ["exposure"],
                        "description": "Shodan host search.", "docs": "https://developer.shodan.io"},
    "greynoise":       {"configured": bool(s.GREYNOISE_API_KEY), "scope": ["reputation"],
                        "description": "GreyNoise community API.", "docs": "https://docs.greynoise.io"},
    "abuseipdb":       {"configured": bool(s.ABUSEIPDB_API_KEY), "scope": ["reputation"],
                        "description": "AbuseIPDB check endpoint.", "docs": "https://docs.abuseipdb.com"},
    "ipinfo":          {"configured": bool(s.IPINFO_TOKEN), "scope": ["geo"],
                        "description": "ipinfo.io host lookup.", "docs": "https://ipinfo.io/developers"},
    "urlscan":         {"configured": bool(s.URLSCAN_API_KEY), "scope": ["web"],
                        "description": "urlscan.io submissions.", "docs": "https://urlscan.io/docs/api/"},
    "hibp":            {"configured": bool(s.HIBP_API_KEY), "scope": ["breach"],
                        "description": "Have I Been Pwned v3.", "docs": "https://haveibeenpwned.com/API/v3"},
    "otx":             {"configured": True, "scope": ["threat_intel"],
                        "description": "AlienVault OTX indicators (enriched with key).", "docs": "https://otx.alienvault.com/api"},
    "opencorporates":  {"configured": bool(s.OPENCORPORATES_API_KEY), "scope": ["corporate"],
                        "description": "OpenCorporates company search.", "docs": "https://api.opencorporates.com"},
    "censys":          {"configured": bool(s.CENSYS_API_ID and s.CENSYS_API_SECRET),
                        "scope": ["exposure", "passive_dns"],
                        "description": "Censys hosts/certs (basic auth).",
                        "docs": "https://search.censys.io/api"},
    "misp_export":     {"configured": True, "scope": ["export"],
                        "description": "MISP event export (v2 JSON).",
                        "docs": "https://www.misp-project.org/openapi/"},
}
