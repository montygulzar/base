"""Favicon hashing (Shodan / FOFA / Censys fingerprint).

Downloads /favicon.txt or /favicon.ico from a URL or domain, base64-
encodes, and computes mmh3 hash (the standard used by Shodan & FOFA).
Emits the hash as a `hash` entity and a 'fingerprint' finding.
"""
from __future__ import annotations
import base64
import httpx
from urllib.parse import urlparse
from ..utils.validators import normalise_domain
from ..utils.ssrf import assert_public, SSRFBlocked
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


def _mmh3_32(data: bytes) -> int:
    """Pure-python MurmurHash3 32-bit (signed), reference impl.
    Avoids a C extension dependency in the container."""
    length = len(data)
    nblocks = length // 4
    h1 = 0
    c1 = 0xcc9e2d51
    c2 = 0x1b873593
    for i in range(nblocks):
        k1 = (data[i*4]) | (data[i*4+1] << 8) | (data[i*4+2] << 16) | (data[i*4+3] << 24)
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF
    tail = data[nblocks*4:]
    k1 = 0
    if len(tail) >= 3: k1 ^= tail[2] << 16
    if len(tail) >= 2: k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= (h1 >> 16); h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= (h1 >> 13); h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= (h1 >> 16)
    # convert to signed i32 (Shodan convention)
    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    url = v if "://" in v else "https://" + normalise_domain(v)
    try:
        assert_public(url)
    except SSRFBlocked as e:
        out.findings.append(Finding("favicon", "ssrf_blocked", {"url": url, "reason": str(e)}, 0.0))
        return out

    tried = [urlparse(url)._replace(path="/favicon.ico").geturl(),
             urlparse(url)._replace(path="/favicon.png").geturl()]
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}, follow_redirects=True) as c:
        for u in tried:
            try:
                r = await c.get(u, timeout=10)
                if r.status_code == 200 and r.content:
                    # Shodan expects base64 with newline every 76 chars + terminal newline
                    b64 = base64.encodebytes(r.content).decode()
                    h = _mmh3_32(b64.encode())
                    out.findings.append(Finding("favicon", "hash", {
                        "url": u, "bytes": len(r.content), "mmh3": h,
                        "shodan_query": f"http.favicon.hash:{h}",
                        "fofa_query": f'icon_hash="{h}"',
                    }, 0.9))
                    out.entities.append(Entity("hash", str(h), {"kind": "favicon_mmh3", "url": u}, 0.85))
                    return out
            except Exception:
                continue
    out.findings.append(Finding("favicon", "not_found", {"tried": tried}, 0.2))
    return out


register(Module(
    key="favicon",
    name="Favicon fingerprint",
    subject_types=["domain", "url"],
    description="Shodan/FOFA mmh3 favicon hash for pivoting.",
    run=run,
))
