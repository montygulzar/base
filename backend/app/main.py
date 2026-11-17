import logging
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from .config import get_settings
from .api import auth as api_auth, investigations, modules as api_modules, integrations as api_integrations, graph, reports, ws, transforms, timeline, misp, stix, schedules, audit, health as api_health

log = logging.getLogger("base")
logging.basicConfig(level=get_settings().LOG_LEVEL)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    log.info("base api starting")
    yield
    log.info("base api stopped")


app = FastAPI(title="base — OSINT platform", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Simple in-process token-bucket per IP; honest-effort, not DDoS-grade.
_BUCKETS: dict[str, tuple[int, float]] = {}
_RATE_LIMIT = get_settings().RATE_LIMIT_PER_MINUTE


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    client = (request.client.host if request.client else "?") + ":" + (request.headers.get("authorization", "")[:16] or "anon")
    now = time.monotonic()
    tokens, last = _BUCKETS.get(client, (_RATE_LIMIT, now))
    # refill
    refill = (now - last) * (_RATE_LIMIT / 60.0)
    tokens = min(_RATE_LIMIT, tokens + refill)
    if tokens < 1:
        return JSONResponse({"detail": "rate limit"}, status_code=429,
                            headers={"retry-after": "5"})
    tokens -= 1
    _BUCKETS[client] = (tokens, now)
    start = time.monotonic()
    resp = await call_next(request)
    resp.headers["x-base-duration-ms"] = str(round((time.monotonic() - start) * 1000, 2))
    return resp

app.include_router(api_auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(investigations.router, prefix="/api/investigations", tags=["investigations"])
app.include_router(api_modules.router, prefix="/api/modules", tags=["modules"])
app.include_router(api_integrations.router, prefix="/api/integrations", tags=["integrations"])
app.include_router(graph.router, prefix="/api/graph", tags=["graph"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
app.include_router(ws.router, prefix="/api/ws", tags=["ws"])
app.include_router(transforms.router, prefix="/api/transforms", tags=["transforms"])
app.include_router(timeline.router, prefix="/api/timeline", tags=["timeline"])
app.include_router(misp.router, prefix="/api/misp", tags=["misp"])
app.include_router(stix.router, prefix="/api/stix", tags=["stix"])
app.include_router(schedules.router, prefix="/api/schedules", tags=["schedules"])
app.include_router(audit.router, prefix="/api/audit", tags=["audit"])
app.include_router(api_health.router, prefix="/api/sources", tags=["sources"])
from .api import exports as api_exports, users as api_users, ingest as api_ingest, compare as api_compare, search as api_search, stats as api_stats, graph_query, notes as api_notes, templates as api_templates, enrich as api_enrich
app.include_router(api_exports.router, prefix="/api/exports", tags=["exports"])
app.include_router(api_users.router, prefix="/api/users", tags=["users"])
app.include_router(api_ingest.router, prefix="/api/ingest", tags=["ingest"])
app.include_router(api_compare.router, prefix="/api/compare", tags=["compare"])
app.include_router(api_search.router, prefix="/api/search", tags=["search"])
app.include_router(api_stats.router, prefix="/api/stats", tags=["stats"])
app.include_router(graph_query.router, prefix="/api/graph", tags=["graph"])
app.include_router(api_notes.router, prefix="/api/notes", tags=["notes"])
app.include_router(api_templates.router, prefix="/api/templates", tags=["templates"])
app.include_router(api_enrich.router, prefix="/api/enrich", tags=["enrich"])
from .api import taxii_server as api_taxii_server, metrics as api_metrics, share as api_share, progress as api_progress, screenshots as api_screenshots
app.include_router(api_taxii_server.router, prefix="/api/taxii_server", tags=["taxii-server"])
app.include_router(api_metrics.router, tags=["metrics"])
app.include_router(api_share.router, prefix="/api/share", tags=["share"])
app.include_router(api_progress.router, prefix="/api/progress", tags=["progress"])
app.include_router(api_screenshots.router, prefix="/api/screenshots", tags=["screenshots"])
from .api import fork as api_fork, jwt_tool as api_jwt_tool, detect as api_detect, recent as api_recent
app.include_router(api_fork.router, prefix="/api/fork", tags=["fork"])
app.include_router(api_jwt_tool.router, prefix="/api/jwt", tags=["jwt"])
app.include_router(api_detect.router, prefix="/api/detect", tags=["detect"])
app.include_router(api_recent.router, prefix="/api/recent", tags=["recent"])
from .api import retention as api_retention, triage as api_triage, bulk as api_bulk
app.include_router(api_retention.router, prefix="/api/retention", tags=["retention"])
app.include_router(api_triage.router, prefix="/api/triage", tags=["triage"])
app.include_router(api_bulk.router, prefix="/api/bulk", tags=["bulk"])
from .api import geojson as api_geojson, jobs as api_jobs, path as api_path, inv_tags as api_inv_tags
app.include_router(api_geojson.router, prefix="/api/geojson", tags=["geojson"])
app.include_router(api_jobs.router, prefix="/api/jobs", tags=["jobs"])
app.include_router(api_path.router, prefix="/api/path", tags=["path"])
app.include_router(api_inv_tags.router, prefix="/api/inv_tags", tags=["inv-tags"])
from .api import module_stats as api_module_stats, merge as api_merge, version as api_version
app.include_router(api_module_stats.router, prefix="/api/module_stats", tags=["module-stats"])
app.include_router(api_merge.router, prefix="/api/merge", tags=["merge"])
app.include_router(api_version.router, prefix="/api/version", tags=["version"])
from .api import zip_export as api_zip, fuzzy as api_fuzzy, apikeys as api_apikeys
app.include_router(api_zip.router, prefix="/api/zip", tags=["zip"])
app.include_router(api_fuzzy.router, prefix="/api/fuzzy", tags=["fuzzy"])
app.include_router(api_apikeys.router, prefix="/api/apikeys", tags=["apikeys"])
from .api import degrees as api_degrees, backup as api_backup, mermaid as api_mermaid, seal as api_seal
app.include_router(api_degrees.router, prefix="/api/degrees", tags=["degrees"])
app.include_router(api_backup.router, prefix="/api/backup", tags=["backup"])
app.include_router(api_mermaid.router, prefix="/api/mermaid", tags=["mermaid"])
app.include_router(api_seal.router, prefix="/api/seal", tags=["seal"])
from .api import global_search as api_global_search, combined_graph as api_combined_graph
app.include_router(api_global_search.router, prefix="/api/global_search", tags=["global-search"])
app.include_router(api_combined_graph.router, prefix="/api/combined_graph", tags=["combined-graph"])
from .api import plans as api_plans
app.include_router(api_plans.router, prefix="/api/plans", tags=["plans"])


@app.get("/api/health")
async def health():
    return {"status": "ok"}
