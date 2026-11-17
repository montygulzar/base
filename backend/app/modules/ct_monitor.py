"""CT log monitor delta — poll crt.sh for new certs for a domain since
a timestamp. Pair with schedules for continuous CT monitoring.
"""
from __future__ import annotations
import httpx
from datetime import datetime, timedelta, timezone
from ..utils.validators import is_domain, normalise_domain
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    d = normalise_domain(subject)
    if not is_domain(d):
        out.findings.append(Finding("ct_monitor", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("domain", d, {}, 0.9))
    cutoff = (datetime.now(tz=timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            r = await c.get(
                "https://crt.sh/", params={"q": f"%.{d}", "output": "json",
                                           "exclude": "expired"}, timeout=25)
            if r.status_code != 200:
                out.findings.append(Finding("ct_monitor", "http_error",
                                            {"status": r.status_code}, 0.1))
                return out
            rows = r.json() if r.text.strip() else []
            new_rows = [row for row in rows
                         if (row.get("not_before") or "").split("T")[0] >= cutoff]
            names = set()
            for row in new_rows:
                for n in (row.get("name_value") or "").splitlines():
                    n = n.strip().lower().lstrip("*.")
                    if "@" in n or " " in n:
                        continue
                    if n.endswith("." + d) or n == d:
                        if is_domain(n):
                            names.add(n)
            out.findings.append(Finding("ct_monitor", "recent",
                                        {"domain": d, "since": cutoff,
                                         "new_cert_count": len(new_rows),
                                         "unique_names": len(names),
                                         "sample": sorted(names)[:50]},
                                        0.9 if new_rows else 0.4))
            for n in sorted(names)[:200]:
                if n == d:
                    continue
                out.entities.append(Entity("domain", n, {"from": "ct_monitor"}, 0.75))
                out.relationships.append(Relationship("domain", n, "domain", d,
                                                      "subdomain_of", "ct_monitor", 0.8))
        except Exception as e:
            out.findings.append(Finding("ct_monitor", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="ct_monitor",
    name="CT log delta (7-day)",
    subject_types=["domain"],
    description="Last-7-days crt.sh CT delta; pair with /schedules for continuous monitoring.",
    run=run,
))
