"""Bitcoin transaction lookup via mempool.space."""
from __future__ import annotations
import re
import httpx
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


TXID_RE = re.compile(r"^[a-fA-F0-9]{64}$")


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    t = (subject or "").strip()
    if not TXID_RE.match(t):
        out.findings.append(Finding("btc_tx", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("hash", t.lower(), {"kind": "btc_txid"}, 0.95))
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            r = await c.get(f"https://mempool.space/api/tx/{t}", timeout=15)
            if r.status_code == 200:
                j = r.json()
                out.findings.append(Finding("mempool", "tx", j, 0.95))
                for v in (j.get("vin") or []):
                    addr = (v.get("prevout") or {}).get("scriptpubkey_address")
                    if addr:
                        out.entities.append(Entity("btc", addr, {"role": "input", "txid": t}, 0.85))
                        out.relationships.append(Relationship("hash", t.lower(), "btc", addr,
                                                              "spent_from", "mempool.space", 0.9))
                for v in (j.get("vout") or []):
                    addr = v.get("scriptpubkey_address")
                    if addr:
                        out.entities.append(Entity("btc", addr, {"role": "output", "txid": t,
                                                                  "value_sat": v.get("value")}, 0.85))
                        out.relationships.append(Relationship("hash", t.lower(), "btc", addr,
                                                              "paid_to", "mempool.space", 0.9))
            else:
                out.findings.append(Finding("mempool", "http_error",
                                            {"status": r.status_code}, 0.1))
        except Exception as e:
            out.findings.append(Finding("mempool", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="btc_tx",
    name="Bitcoin transaction",
    subject_types=["document", "btc"],
    description="mempool.space tx lookup; input/output addresses added to graph.",
    run=run,
))
