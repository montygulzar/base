"""Nuclei-lite — a hardcoded, bounded subset of well-known public-facing
vulnerability / misconfiguration checks. Every check is a single HTTP
request with tight timeouts, SSRF-guarded, keyless.

NOT a replacement for ProjectDiscovery nuclei — a triage helper for
quick exposure sanity-checks.
"""
from __future__ import annotations
import httpx
from urllib.parse import urljoin
from ..utils.ssrf import assert_public, SSRFBlocked
from ..utils.validators import normalise_domain
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


CHECKS = [
    # (name, path, match_text, severity)
    ("exposed_git",      "/.git/config",           "[core]",        "high"),
    ("exposed_env",      "/.env",                  "APP_",          "high"),
    ("exposed_svn",      "/.svn/entries",          "",              "medium"),
    ("exposed_dsstore",  "/.DS_Store",             "Bud1",          "low"),
    ("backup_sql",       "/backup.sql",            "INSERT ",       "high"),
    ("phpinfo",          "/phpinfo.php",           "PHP Version",   "high"),
    ("wp_admin",         "/wp-admin/",             "WordPress",     "low"),
    ("admin_login",      "/admin/",                "login",         "low"),
    ("server_status",    "/server-status",         "Apache Server", "medium"),
    ("adminer",          "/adminer.php",           "Adminer",       "medium"),
    ("phpmyadmin",       "/phpmyadmin/",           "phpMyAdmin",    "medium"),
    ("env_json",         "/env.json",              "APP_",          "medium"),
    ("api_swagger",      "/swagger-ui/",           "swagger",       "low"),
    ("api_openapi",      "/openapi.json",          "\"openapi\"",   "low"),
    ("elasticsearch",    "/_cat/indices",          "",              "high"),
    ("kibana",           "/app/kibana",            "Kibana",        "medium"),
    ("jenkins",          "/login?from=%2F",        "Jenkins",       "medium"),
    ("airflow",          "/airflow/",              "Airflow",       "medium"),
    ("prometheus",       "/metrics",               "# HELP",        "low"),
    ("graphql_playground","/graphql",              "query",         "low"),
]


async def _run_one(c: httpx.AsyncClient, base: str, name: str, path: str,
                   needle: str, severity: str) -> dict:
    url = urljoin(base, path)
    try:
        r = await c.get(url, timeout=8, follow_redirects=False)
    except Exception as e:
        return {"check": name, "url": url, "error": str(e)[:200]}
    text = (r.text or "")[:4000]
    hit = r.status_code == 200 and (not needle or needle.lower() in text.lower())
    return {"check": name, "url": url, "status": r.status_code,
            "hit": hit, "severity": severity if hit else None}


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    url = v if "://" in v else "https://" + normalise_domain(v)
    try:
        assert_public(url)
    except SSRFBlocked as e:
        out.findings.append(Finding("nuclei_lite", "ssrf_blocked",
                                    {"url": url, "reason": str(e)}, 0.0))
        return out
    out.entities.append(Entity("url", url, {}, 0.9))
    base = url if url.endswith("/") else url + "/"
    async with httpx.AsyncClient(headers={"user-agent": "Mozilla/5.0 base-osint/0.1"}) as c:
        results = []
        for name, path, needle, sev in CHECKS:
            r = await _run_one(c, base, name, path, needle, sev)
            results.append(r)
    hits = [r for r in results if r.get("hit")]
    severity_counts: dict[str, int] = {}
    for h in hits:
        severity_counts[h["severity"]] = severity_counts.get(h["severity"], 0) + 1
    out.findings.append(Finding("nuclei_lite", "scan",
                                {"total_checks": len(results),
                                 "hits": hits, "severity_counts": severity_counts,
                                 "all_results": results}, 0.95))
    for h in hits:
        out.findings.append(Finding("nuclei_lite", f"hit:{h['check']}",
                                    {"url": h["url"], "severity": h["severity"]},
                                    0.9))
    return out


register(Module(
    key="nuclei_lite",
    name="Nuclei-lite exposure checks",
    subject_types=["url", "domain"],
    description="20 fixed exposure / misconfig probes (git, env, phpinfo, kibana, …).",
    run=run,
))
