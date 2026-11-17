# Architecture

## Overview

`base` is split into four runtime processes behind docker compose:

1. **backend** — FastAPI (API + static orchestrator fallback for background tasks via `asyncio.create_task`)
2. **worker** — arq worker that reads Redis and runs `orchestrator.plan_and_run`
3. **postgres** — relational storage (investigations, subjects, jobs, entities, relationships, findings, audit)
4. **redis** — queue + rate-limit cache
5. **frontend** — Next.js (App Router, TS, Tailwind)

```
 ┌────────┐    HTTP/JSON   ┌───────────┐    SQLAlchemy    ┌──────────┐
 │  Next  │◀──────────────▶│  FastAPI  │◀────────────────▶│ Postgres │
 └────────┘                └─────┬─────┘                  └──────────┘
      ▲                          │ enqueue
      │ WebSocket (job status)   ▼
      │                        ┌─────┐    Redis    ┌──────────┐
      └───────────────────────▶│ ws  │◀──────────▶│  Worker  │
                               └─────┘            └────┬─────┘
                                                      │
                                                 modules → integrations
                                                      │
                                                   correlation
```

## Layers

- **API layer** — `app/api/*` — authentication, investigations, modules, integrations, graph, reports, ws
- **Collection engine** — `app/modules/*` — each module implements `run(subject, ctx) -> CollectionResult`
- **Integration adapters** — thin HTTPX clients inside each module (one per provider). Registry metadata lives in `app/integrations/__init__.py`.
- **Orchestrator** — `app/orchestrator.py` — subject-type-driven plan, bounded concurrency, per-job persistence
- **Correlation engine** — `app/correlation.py` — second-order relationships across findings
- **Storage** — SQLAlchemy 2.x async, Postgres
- **Reporting** — `app/reporting.py` — markdown / HTML / PDF renderers; JSON and CSV built straight from the bundle

## Data model

| Table | Purpose |
| --- | --- |
| `users` | auth / RBAC |
| `investigations` | top-level workspace |
| `subjects` | inputs attached to an investigation |
| `jobs` | one module run × one subject |
| `entities` | normalised graph nodes (domain, ip, asn, email, username, url, org, cve, hash, file, cert) |
| `relationships` | typed, provenance-bearing edges |
| `findings` | module-level evidence blobs with `source`, `kind`, `confidence`, `collected_at` |
| `audit_log` | user action trail |
| `integration_status` | per-provider last_ok / last_error / rate limit |

## Provenance

Every finding records `module`, `source`, `kind`, `confidence`, `collected_at`.
Every relationship records `source`, `confidence`, `evidence`.
A report can therefore be traced from conclusion → evidence → source request.

## Extensibility

Adding a module:

1. Create `backend/app/modules/<key>.py` defining an `async def run(subject, ctx) -> CollectionResult`.
2. `register(Module(key=..., name=..., subject_types=[...], run=run))`
3. Import it from `app/modules/__init__.py`.

Adding an integration: add its env variable to `config.py`, the registry entry in `app/integrations/__init__.py`, and the call from whichever module uses it. Modules must always emit a `source_unavailable` finding when a key is missing — never a fake result.
