import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .config import get_settings
from .api import auth as api_auth, investigations, modules as api_modules, integrations as api_integrations, graph, reports, ws

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

app.include_router(api_auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(investigations.router, prefix="/api/investigations", tags=["investigations"])
app.include_router(api_modules.router, prefix="/api/modules", tags=["modules"])
app.include_router(api_integrations.router, prefix="/api/integrations", tags=["integrations"])
app.include_router(graph.router, prefix="/api/graph", tags=["graph"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
app.include_router(ws.router, prefix="/api/ws", tags=["ws"])


@app.get("/api/health")
async def health():
    return {"status": "ok"}
