"""Bitcoin address OSINT via mempool.space — free, no key."""
from __future__ import annotations
import re
import httpx
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


BTC_RE = re.compile(r"^(bc1[a-zA-HJ-NP-Z0-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    a = (subject or "").strip()
    if not BTC_RE.match(a):
        out.findings.append(Finding("btc_addr", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("btc", a, {}, 0.95))
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            r = await c.get(f"https://mempool.space/api/address/{a}", timeout=15)
            if r.status_code == 200:
                out.findings.append(Finding("mempool", "address", r.json(), 0.95))
            else:
                out.findings.append(Finding("mempool", "http_error",
                                            {"status": r.status_code}, 0.1))
            # last 10 txs
            rt = await c.get(f"https://mempool.space/api/address/{a}/txs", timeout=25)
            if rt.status_code == 200:
                txs = rt.json() or []
                out.findings.append(Finding("mempool", "txs",
                                            {"count": len(txs),
                                             "sample": [{"txid": t.get("txid"),
                                                         "time": (t.get("status") or {}).get("block_time"),
                                                         "fee": t.get("fee"),
                                                         "size": t.get("size")}
                                                        for t in txs[:10]]},
                                            0.9))
        except Exception as e:
            out.findings.append(Finding("mempool", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="btc_addr",
    name="Bitcoin address",
    subject_types=["btc"],
    description="mempool.space address stats + recent transactions.",
    run=run,
))
