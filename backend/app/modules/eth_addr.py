"""Ethereum address OSINT via Blockscout (keyless public endpoint)."""
from __future__ import annotations
import re
import httpx
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


ETH_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    a = (subject or "").strip()
    if not ETH_RE.match(a):
        out.findings.append(Finding("eth_addr", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("eth", a, {}, 0.95))
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        # Blockscout mainnet endpoint
        try:
            r = await c.get(f"https://eth.blockscout.com/api/v2/addresses/{a}", timeout=20)
            if r.status_code == 200:
                out.findings.append(Finding("blockscout", "address", r.json(), 0.9))
            else:
                out.findings.append(Finding("blockscout", "http_error",
                                            {"status": r.status_code,
                                             "body": r.text[:200]}, 0.1))
        except Exception as e:
            out.findings.append(Finding("blockscout", "error", {"error": str(e)}, 0.1))
        try:
            rt = await c.get(f"https://eth.blockscout.com/api/v2/addresses/{a}/transactions",
                             params={"items_count": 10}, timeout=20)
            if rt.status_code == 200:
                items = (rt.json() or {}).get("items") or []
                out.findings.append(Finding("blockscout", "transactions",
                                            {"count": len(items),
                                             "sample": [{"hash": t.get("hash"),
                                                         "from": (t.get("from") or {}).get("hash"),
                                                         "to": (t.get("to") or {}).get("hash"),
                                                         "value": t.get("value"),
                                                         "timestamp": t.get("timestamp")}
                                                        for t in items[:10]]},
                                            0.9))
        except Exception as e:
            out.findings.append(Finding("blockscout", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="eth_addr",
    name="Ethereum address",
    subject_types=["eth"],
    description="Blockscout address + recent transactions (keyless).",
    run=run,
))
