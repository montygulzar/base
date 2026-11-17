"""API smoke — the app imports cleanly and advertises its routes."""
from app.main import app


def test_routes_mounted():
    paths = {r.path for r in app.routes}
    assert "/api/health" in paths
    assert any(p.startswith("/api/auth/") for p in paths)
    assert any(p.startswith("/api/investigations") for p in paths)
    assert any(p.startswith("/api/modules") for p in paths)
    assert any(p.startswith("/api/integrations") for p in paths)
    assert any(p.startswith("/api/graph/") for p in paths)
    assert any(p.startswith("/api/reports/") for p in paths)
