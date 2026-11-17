"""API smoke — the app imports cleanly and advertises its routes.

Newer FastAPI wraps mounted routers in an internal `_IncludedRouter` type,
so we walk the resolved router tree instead of looking at top-level routes.
"""
from fastapi.routing import APIRoute, APIWebSocketRoute
from app.main import app


def _all_paths(router) -> set[str]:
    paths: set[str] = set()
    for r in router.routes:
        if isinstance(r, (APIRoute, APIWebSocketRoute)):
            paths.add(r.path)
        inner = getattr(r, "routes", None)
        if inner:
            for ir in inner:
                if isinstance(ir, (APIRoute, APIWebSocketRoute)):
                    paths.add(ir.path)
    return paths


def test_routes_mounted():
    # Importing individual routers must at least work and expose some routes.
    from app.api import auth, investigations, modules, integrations, graph, reports, transforms, timeline, misp, ws
    for r in (auth.router, investigations.router, modules.router, integrations.router,
              graph.router, reports.router, transforms.router, timeline.router,
              misp.router, ws.router):
        assert len(r.routes) >= 1, f"empty router: {r}"
    paths = _all_paths(app.router)
    assert "/api/health" in paths
