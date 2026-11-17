"""Detect common unauth'd services.

Specifically:
- Redis without auth (TCP connect + 'PING' command)
- Elasticsearch public (/ returns ES banner)
- Kubernetes API unauth (/api returns the APIVersions doc)
- Memcached ping (banner-less)
- Docker API (/version returns Docker version)

SSRF-guarded on hostnames.
"""
from __future__ import annotations
import asyncio
import httpx
from ..utils.validators import is_ip, is_domain, is_private_ip
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


async def _tcp_ping(host: str, port: int, payload: bytes) -> dict:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=4)
    except Exception as e:
        return {"port": port, "error": str(e)[:200]}
    try:
        writer.write(payload); await writer.drain()
        data = await asyncio.wait_for(reader.read(256), timeout=3)
        return {"port": port, "response": data.decode(errors="replace").strip()[:200]}
    finally:
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    if not (is_ip(v) or is_domain(v)):
        out.findings.append(Finding("open_services", "invalid_input", {"input": subject}, 0.1))
        return out
    import socket
    try:
        infos = socket.getaddrinfo(v, None)
    except Exception as e:
        out.findings.append(Finding("open_services", "dns_fail", {"error": str(e)}, 0.1))
        return out
    for _, _, _, _, sa in infos:
        if is_private_ip(sa[0]):
            out.findings.append(Finding("open_services", "ssrf_blocked",
                                        {"host": v, "resolved_private": sa[0]}, 0.0))
            return out
    out.entities.append(Entity("ip" if is_ip(v) else "domain", v, {}, 0.9))

    redis = await _tcp_ping(v, 6379, b"PING\r\n")
    memc = await _tcp_ping(v, 11211, b"stats\r\n")
    out.findings.append(Finding("open_services", "redis_ping",
                                {"host": v, **redis,
                                 "unauth": "response" in redis and "+PONG" in redis.get("response", "")},
                                0.95 if "response" in redis else 0.4))
    out.findings.append(Finding("open_services", "memcached",
                                {"host": v, **memc,
                                 "responsive": "response" in memc and "STAT" in memc.get("response", "")},
                                0.9 if "response" in memc else 0.4))

    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        for port, path, name in [(9200, "/", "elasticsearch"), (8443, "/api", "k8s_api"),
                                  (6443, "/api", "k8s_api_alt"), (2375, "/version", "docker_api"),
                                  (2376, "/version", "docker_api_tls")]:
            scheme = "https" if port in (8443, 6443, 2376) else "http"
            try:
                r = await c.get(f"{scheme}://{v}:{port}{path}", timeout=5,
                                follow_redirects=False)
                sample = (r.text or "")[:400]
                hit = r.status_code == 200 and name in sample.lower()
                out.findings.append(Finding("open_services", name,
                                            {"port": port, "status": r.status_code,
                                             "body_sample": sample, "hit": hit},
                                            0.95 if hit else 0.4))
            except Exception:
                pass
    return out


register(Module(
    key="open_services",
    name="Common unauth'd services",
    subject_types=["ip", "domain"],
    description="Redis / Memcached / Elasticsearch / Kubernetes / Docker exposure probes.",
    run=run,
))
