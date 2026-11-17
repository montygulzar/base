"""API smoke — the app mounts a full endpoint surface. Walks through
fastapi's _IncludedRouter wrapper via `original_router`.
"""
from fastapi.routing import APIRoute, APIWebSocketRoute
from app.main import app


def _walk(router, prefix, out):
    for r in router.routes:
        if isinstance(r, (APIRoute, APIWebSocketRoute)):
            out.add(prefix + r.path)
        elif type(r).__name__ == "_IncludedRouter":
            sub_prefix = getattr(getattr(r, "include_context", None), "prefix", "") or ""
            _walk(r.original_router, prefix + sub_prefix, out)


def test_routes_mounted():
    out = set()
    _walk(app.router, "", out)
    required_prefixes = [
        "/api/health", "/api/auth/", "/api/investigations",
        "/api/modules", "/api/integrations", "/api/graph/",
        "/api/reports/", "/api/transforms/", "/api/timeline/",
        "/api/misp/", "/api/stix/", "/api/schedules", "/api/audit",
    ]
    for p in required_prefixes:
        assert any(path.startswith(p) for path in out), f"missing route group: {p}"
    assert len(out) >= 25
