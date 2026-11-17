"""Tiny in-process per-provider rate limiter. Call `await gate('shodan')`
before each outbound request; limits default to env.RATE_LIMIT_PER_MINUTE
and can be overridden per provider.
"""
from __future__ import annotations
import asyncio
import time
from collections import deque, defaultdict
from ..config import get_settings

_LOCK = asyncio.Lock()
_calls: dict[str, deque[float]] = defaultdict(deque)
_LIMITS: dict[str, int] = {
    "shodan": 60, "virustotal": 4, "greynoise": 30, "abuseipdb": 60,
    "ipinfo": 60, "hibp": 10, "securitytrails": 50, "urlscan": 30,
    "censys": 5, "otx": 60, "opencorporates": 30,
}


async def gate(provider: str):
    limit = _LIMITS.get(provider, get_settings().RATE_LIMIT_PER_MINUTE)
    window = 60.0
    async with _LOCK:
        q = _calls[provider]
        now = time.monotonic()
        while q and q[0] < now - window:
            q.popleft()
        if len(q) >= limit:
            wait = window - (now - q[0])
            await asyncio.sleep(max(wait, 0.05))
        _calls[provider].append(time.monotonic())
