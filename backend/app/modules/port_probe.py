"""Bounded TCP port probe.

NOT a port scanner. Checks a short, fixed list of common service ports
against a resolved target, with tight per-connect timeouts. SSRF-guarded;
private / loopback destinations refused.
"""
from __future__ import annotations
import asyncio
import socket
from ..utils.validators import is_ip, is_domain, is_private_ip
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 1521,
         2375, 3306, 3389, 5432, 5900, 5984, 6379, 7777, 8000, 8080, 8443, 9000,
         9200, 11211, 27017]


async def _probe(host: str, port: int, timeout: float = 1.2) -> tuple[int, bool, str]:
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        banner = ""
        try:
            writer.write(b"\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(256), timeout=0.8)
            banner = data.decode(errors="replace").strip()[:200]
        except Exception:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port, True, banner
    except Exception:
        return port, False, ""


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    if is_ip(v):
        host = v
    elif is_domain(v):
        host = v
    else:
        out.findings.append(Finding("port_probe", "invalid_input", {"input": v}, 0.1))
        return out

    try:
        infos = socket.getaddrinfo(host, None)
    except Exception as e:
        out.findings.append(Finding("port_probe", "dns_fail", {"host": host, "error": str(e)}, 0.1))
        return out
    for _, _, _, _, sa in infos:
        ip = sa[0]
        if is_private_ip(ip):
            out.findings.append(Finding("port_probe", "ssrf_blocked",
                                        {"host": host, "resolved_private": ip}, 0.0))
            return out

    out.entities.append(Entity("domain" if is_domain(v) else "ip", v, {}, 0.9))
    sem = asyncio.Semaphore(16)
    async def guarded(p):
        async with sem:
            return await _probe(host, p)
    results = await asyncio.gather(*[guarded(p) for p in PORTS])
    open_ports = [{"port": p, "banner": b} for p, ok, b in results if ok]
    out.findings.append(Finding("port_probe", "summary",
                                {"checked": len(PORTS), "open": len(open_ports), "ports": open_ports}, 0.9))
    return out


register(Module(
    key="port_probe",
    name="Bounded port probe",
    subject_types=["ip", "domain"],
    description="Short list of common ports, tight timeouts, SSRF-guarded.",
    run=run,
))
