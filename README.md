# base — OSINT Investigation Platform

Modular, extensible, professional-grade OSINT platform. Unified investigation
environment combining domain / IP / email / username / company / media /
document / web / CTI collection with a correlation engine, interactive graph
workspace, and reproducible reporting.

## Stack

- **Backend:** Python 3.11, FastAPI, SQLAlchemy 2.x, asyncpg, Redis, arq workers
- **Frontend:** Next.js 14 (App Router), TypeScript, Tailwind, React Flow
- **Storage:** PostgreSQL (primary), Redis (queue + cache). Neo4j optional.
- **Infra:** Docker Compose, env-based config

## Quick start

```bash
cp .env.example .env
# edit .env — at minimum set JWT_SECRET; API keys optional (modules report "unconfigured")
docker compose up --build
```

- API:        http://localhost:8000/docs
- Frontend:   http://localhost:3000
- Default admin: `admin@base.local` / `admin` (change immediately)

## Modules

| Module | Collector | External sources (optional keys) |
| --- | --- | --- |
| Domain | `modules.domain` | crt.sh, VirusTotal, SecurityTrails, urlscan |
| IP | `modules.ip` | Shodan, GreyNoise, AbuseIPDB, IPinfo, BGPView, RIPEstat |
| Email | `modules.email` | HIBP, DNS/MX/SPF/DMARC (built-in) |
| Username | `modules.username` | 70+ sites (Sherlock-style, built-in) |
| Company | `modules.company` | OpenCorporates (optional), SEC EDGAR |
| Media | `modules.media` | ExifTool, Pillow, perceptual hash |
| Documents | `modules.documents` | PyMuPDF, python-docx, openpyxl, OCR (Tesseract) |
| CTI | `modules.cti` | NVD, MITRE, OTX, ThreatFox, abuse.ch |
| Web | `modules.web` | HTTP probing, robots/sitemap, tech fingerprinting |

All sources that require API keys will register as `unconfigured` and are
skipped gracefully — never substituted with fake data.

## Layout

```
backend/   FastAPI app, modules, orchestrator, correlation, worker, reports
frontend/  Next.js app — dashboard, investigation views, graph workspace
docs/      architecture, modules, deploy, troubleshooting
scripts/   bootstrap, seed, dev helpers
```

See `docs/architecture.md` for the full design and `docs/modules.md` for module
contracts.

## Licence

MIT. Respects upstream licences of every project drawn on for inspiration; no
upstream source is vendored.
