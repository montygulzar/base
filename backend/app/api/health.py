"""Per-integration health check endpoint.

Pings a cheap, well-known endpoint on each integration and records
IntegrationStatus.last_ok_at / last_error. Returns a map per provider.
"""
from __future__ import annotations
import asyncio
from datetime import datetime
import httpx
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..config import get_settings
from ..models import IntegrationStatus

router = APIRouter()


CHECKS: dict[str, tuple[str, dict]] = {
    # provider: (url, headers)
    "crt.sh":          ("https://crt.sh/?q=example.com&output=json&limit=1", {}),
    "bgpview":         ("https://api.bgpview.io/asn/15169", {}),
    "ripestat":        ("https://stat.ripe.net/data/network-info/data.json?resource=8.8.8.8", {}),
    "hackertarget":    ("https://api.hackertarget.com/hostsearch/?q=example.com", {}),
    "rapiddns":        ("https://rapiddns.io/", {}),
    "anubis":          ("https://jldc.me/anubis/subdomains/example.com", {}),
    "subdomain.center":("https://api.subdomain.center/?domain=example.com", {}),
    "bufferover":      ("https://tls.bufferover.run/dns?q=.example.com", {}),
    "wayback":         ("https://archive.org/wayback/available?url=example.com", {}),
    "duckduckgo":      ("https://html.duckduckgo.com/", {}),
    "threatfox":       ("https://threatfox-api.abuse.ch/api/v1/", {}),
    "nvd":             ("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228", {}),
    "sec_edgar":       ("https://data.sec.gov/submissions/CIK0000320193.json",
                        {"user-agent": "base-osint/0.1 research@local"}),
    "internetdb":      ("https://internetdb.shodan.io/8.8.8.8", {}),
}


async def _check(name: str, url: str, headers: dict) -> tuple[str, bool, str]:
    try:
        async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1", **headers}) as c:
            r = await c.get(url, timeout=12)
            ok = 200 <= r.status_code < 400
            return name, ok, "" if ok else f"status={r.status_code}"
    except Exception as e:
        return name, False, str(e)[:200]


@router.post("/check")
async def check_all(_: object = Depends(current_user), db: AsyncSession = Depends(get_session)):
    results = await asyncio.gather(*[_check(n, u, h) for n, (u, h) in CHECKS.items()])
    now = datetime.utcnow()
    out: list[dict] = []
    for name, ok, err in results:
        row = await db.get(IntegrationStatus, name)
        if not row:
            row = IntegrationStatus(name=name, configured=True)
            db.add(row)
        if ok:
            row.last_ok_at = now
            row.last_error = ""
        else:
            row.last_error = err
        out.append({"name": name, "ok": ok, "error": err})
    await db.commit()
    return {"checked": len(out), "results": out, "at": now.isoformat()}
