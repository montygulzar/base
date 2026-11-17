"""SSRF guard. Resolve the host and refuse private / link-local / loopback
destinations. Call `assert_public(url)` before any user-supplied fetch.
"""
from __future__ import annotations
import ipaddress
import socket
from urllib.parse import urlparse


class SSRFBlocked(ValueError):
    pass


def _is_safe_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local
                or a.is_multicast or a.is_reserved or a.is_unspecified)


def assert_public(url: str) -> str:
    p = urlparse(url if "://" in url else "https://" + url)
    if p.scheme not in ("http", "https"):
        raise SSRFBlocked(f"scheme not allowed: {p.scheme}")
    host = p.hostname or ""
    if not host:
        raise SSRFBlocked("no host")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise SSRFBlocked(f"dns fail: {e}")
    for fam, _, _, _, sock in infos:
        ip = sock[0]
        if not _is_safe_ip(ip):
            raise SSRFBlocked(f"{host} resolves to non-public {ip}")
    return url
