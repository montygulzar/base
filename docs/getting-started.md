# Getting started with `base`

A walkthrough from a fresh clone to a running investigation, and the
ins-and-outs of how the pieces hang together.

---

## 0 · What this is

`base` is a self-hosted OSINT investigation platform. You point it at a
domain / ip / email / username / phone / crypto address / company /
file and it fans out to **110 collection modules** that pull from
public sources (plus optional keyed ones), normalises the results into
a graph of typed entities + typed, provenance-bearing relationships,
then lets you report, correlate, pivot, and export.

The whole thing runs as a single `docker compose up` on one machine.

---

## 1 · The one-minute boot

```bash
git clone https://github.com/montygulzar/base
cd base
cp .env.example .env
docker compose up --build
```

Then:

| URL | What it is |
| --- | --- |
| http://localhost:3000 | Next.js frontend |
| http://localhost:8000/docs | FastAPI interactive OpenAPI docs |
| http://localhost:8000/metrics | Prometheus scrape (no auth) |

Default admin login: `admin@base.app` / `admin`. **Change it.**

The compose file brings up five services:

```
┌─ postgres    (primary store)
├─ redis       (queue + cache)
├─ backend     (FastAPI + uvicorn)
├─ worker      (arq — pulls from redis, runs collection)
└─ frontend    (Next.js dev server)
```

If `docker` isn't available on your box, you can also run the backend
against sqlite for dev:

```bash
cd backend
pip install -r requirements.txt
DATABASE_URL="sqlite+aiosqlite:///./base.db" \
JWT_SECRET=please-change-me \
BOOTSTRAP_ADMIN_EMAIL=admin@base.app BOOTSTRAP_ADMIN_PASSWORD=admin \
python -m app.bootstrap                         # one-time: seed admin
uvicorn app.main:app --reload
```

and in another shell:

```bash
cd frontend
npm install
npm run dev
```

---

## 2 · Core concepts

### Subject
A thing you're investigating — the input to a plan. 10 subject types:

```
domain  ip  email  username  company  url  document  media  phone  btc  eth
```

### Investigation
A workspace. Holds one or more subjects, every job that ever ran against
it, every entity + relationship in its graph, every finding with source
provenance, a status (`draft` / `running` / `completed` / `error` /
`sealed`), tags, notes, schedules, and audit entries.

### Module
A single collector. Signature:

```python
async def run(subject: str, ctx: RunContext) -> CollectionResult
```

Returns `findings` (evidence, with source + confidence + kind + JSON
data), `entities` (graph nodes) and `relationships` (typed edges).

Modules **never fabricate data.** If a source needs an API key and the
key is missing, the module emits a `source_unavailable` finding and
skips.

### Finding
The atomic unit of evidence. Always carries `module`, `source`, `kind`,
`confidence`, `collected_at`, and a `data` dict with the raw shape the
source returned. You can trace any conclusion back to the request that
produced it.

### Entity
A normalised graph node. Types include: `domain`, `ip`, `email`, `url`,
`username`, `org`, `asn`, `cve`, `hash`, `file`, `phone`, `btc`, `eth`,
`ttp`. De-duped by `(investigation_id, type, value)`.

### Relationship
A typed, directional edge with its own `source`, `confidence`, and
`evidence`. Types include `resolves_to`, `subdomain_of`, `co_hosted_with`,
`announced_by`, `same_asn_as`, `shares_cert_with`, `typosquat_of`,
`mentioned_in_code`, `exposed_to`, `cert_for`, `ptr_to`, …

### Plan
The default ordered list of modules to run for a subject of a given type.
Lives in `backend/app/orchestrator.py` as `PLAN`. For `domain` it's
currently 30+ modules. You can see the live plan at `GET /api/plans`.

### Orchestrator
Walks the plan, creates a `Job` row per (subject × module), executes
them with bounded concurrency (`MAX_CONCURRENT_COLLECTORS`), persists
findings/entities/relationships, and runs the correlation engine when
everything settles.

### Correlation engine
After every run, derives second-order edges across the graph —
co-hosted domains, same-ASN entities, same-mail-domain accounts, CVEs
auto-extracted from any finding text, favicon clusters, honeypot
signals, takeover candidates, and the composite `risk` score (0–100
across 6 weighted components).

### Module (deferred) vs. integration (static)
A **module** is runtime code. An **integration** is a declarative
registry entry (`backend/app/integrations/__init__.py`) that reports
whether a provider is configured, what it's for, and where its docs
are. The frontend `/integrations` page reads this registry.

---

## 3 · First investigation

Three ways to start one:

### a) UI — the dashboard triage bar
Paste anything (domain, ip, email, hash, CVE, phone, BTC address, URL,
etc.) into the box at the top of the dashboard and hit **triage**.
`base` autodetects the subject type via `/api/detect`, creates an
investigation, runs the default plan, and jumps you to the detail page.

### b) UI — the investigations list
Investigations → **new investigation** → pick name + any subjects →
on the detail view click **run default plan** or **pick modules…**.

### c) CLI
```bash
scripts/base_cli.py login admin@base.app admin
scripts/base_cli.py new "my-invx" --subject domain:iana.org
scripts/base_cli.py run <inv-id>
scripts/base_cli.py findings <inv-id>
scripts/base_cli.py export <inv-id> pdf > report.pdf
scripts/base_cli.py export <inv-id> graphml > graph.graphml
```

### What you see
- `/api/progress/{inv}` reports % done + per-status counts
- `/api/jobs/{inv}/retry` individually or `/redrive_failed` for the
  whole investigation
- A live SWR-polled `recent findings` column on the dashboard
- The detail view's **findings** tab with full-text search
- The **graph** tab — React Flow + dagre LR layout, a confidence
  slider, node-click → inspector drawer with attributes + analyst
  notes + an **expand (run modules)** button

---

## 4 · The pieces of the UI

| Page | What it does |
| --- | --- |
| `/` | Dashboard: triage bar, 4 stat tiles, recent findings, source health w/ ping button, investigation list |
| `/investigations` | CRUD |
| `/investigations/[id]` | Overview + findings (inline search) + graph (confidence slider + node drawer) + jobs. Buttons: run default plan / pick modules / md / html / pdf / csv / json / misp / stix / graphml / gexf / geojson / zip |
| `/modules` | Full catalogue — 110 cards with search + subject-type filter |
| `/scratchpad` | Fire one module at one value without persisting anything |
| `/analytics` | Findings-per-day SVG line chart + top modules + top sources (7 / 14 / 30 / 90 day window) |
| `/integrations` | Per-source configured / docs-link / last-error |
| `/schedules` | Recurring investigation runs |
| `/templates` | Named plan presets ("standard domain workup") |
| `/reports` | Per-investigation export matrix |
| `/users` | Admin: CRUD + role change |
| `/audit` | Admin: live audit log |
| `/settings` | Admin: runtime flags + secret-presence table (never values) |
| `/login` | JWT login |

Header has a global search box (hits `/api/global_search` across every
investigation's entities / findings / investigations).

---

## 5 · The API in groups

| Group | Example endpoints |
| --- | --- |
| Auth & users | `/api/auth/login`, `/api/auth/me`, `/api/users` |
| Investigations | `/api/investigations`, `/subjects`, `/run`, `/jobs`, `/findings`, `/upload`, `/progress`, `/fork`, `/stats`, `/timeline` |
| Data ops | `/api/ingest`, `/api/csv_ingest`, `/api/detect`, `/api/search`, `/api/global_search`, `/api/fuzzy`, `/api/compare`, `/api/recent`, `/api/bulk/delete`, `/api/bulk/tag`, `/api/merge`, `/api/notes`, `/api/inv_tags`, `/api/retention` |
| Graph | `/api/graph`, `/api/graph/.../traverse`, `/api/path`, `/api/transforms/.../expand`, `/api/degrees`, `/api/combined_graph` |
| Exports | `/api/reports/*.json|md|html|pdf|csv`, `/api/stix`, `/api/misp`, `/api/exports/*.graphml|gexf`, `/api/geojson`, `/api/mermaid`, `/api/zip`, `/api/backup`, `/api/bulk_export` |
| Lifecycle | `/api/templates`, `/api/schedules`, `/api/share`, `/api/seal`, `/api/triage`, `/api/scratchpad`, `/api/enrich` |
| Observability | `/api/sources/check`, `/api/module_stats`, `/api/stats`, `/api/analytics`, `/api/version`, `/api/audit`, `/api/config`, `/metrics` |
| Interop | `/api/taxii_server/*`, `/api/stix/{id}/import`, `/api/jwt/decode`, `/api/apikeys`, `/api/ws/*` |

Full table in `docs/api.md`.

---

## 6 · Config & secrets

`backend/app/config.py` reads `.env` via pydantic-settings. The most
important knobs:

| Var | Default | Why |
| --- | --- | --- |
| `JWT_SECRET` | dev value | **set a strong value in prod** |
| `DATABASE_URL` | postgres URL from compose | swap to `sqlite+aiosqlite:///./base.db` for single-node dev |
| `REDIS_URL` | from compose | arq workers only |
| `MAX_CONCURRENT_COLLECTORS` | 8 | bounded concurrency per investigation |
| `RATE_LIMIT_PER_MINUTE` | 120 | per-IP+auth-prefix on the API itself |
| `HTTP_TIMEOUT_SECONDS` | 20 | collector default |
| `BOOTSTRAP_ADMIN_EMAIL` / `_PASSWORD` | `admin@base.app` / `admin` | seed only if the users table is empty |

### API keys
Every optional-key integration has an env var — e.g.
`SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY`, `GITHUB_TOKEN`,
`CENSYS_API_ID` + `_SECRET`, `FOFA_API_EMAIL` + `_KEY`,
`ZOOMEYE_API_KEY`, `INTELX_API_KEY`, `HIBP_API_KEY`,
`OTX_API_KEY`, `OPENCORPORATES_API_KEY`,
`TINEYE_API_USER` + `_KEY`, `BING_VISUAL_API_KEY`,
`COMPANIESHOUSE_API_KEY`, `NUMVERIFY_API_KEY`,
`EMAILREP_API_KEY`, `OPENCTI_URL` + `_TOKEN`,
`ELASTICSEARCH_URL` + `_API_KEY`, `WEBHOOK_URL`.

The `/settings` page shows which are set without exposing the values.

The ~45 keyless sources light up out of the box: crt.sh, DNS, RDAP,
BGPView, RIPEstat, Wayback, DuckDuckGo, hackertarget, rapiddns, anubis,
subdomain.center, bufferover, Shodan InternetDB, CrowdSec, ThreatFox,
URLhaus, MalwareBazaar, FeodoTracker, NVD, EPSS, CISA KEV, OSV,
OpenSanctions, Ahmia, GitHub public, Bluesky, Mastodon, Reddit,
Gravatar, SEC EDGAR, mempool.space, Blockscout, Tranco, Spamhaus DBL,
Tor exit list, CertSpotter, DNSBLs, OpenPhish, PhishStats, Chromium
HSTS preload, HackerNews Algolia, Exploit-DB CSV, ProjectDiscovery
Chaos BB list, abuse.ch, tldrsummary of CT logs…

---

## 7 · Extending

### Add a module
```python
# backend/app/modules/my_mod.py
from .base import (Module, Finding, Entity, Relationship,
                   CollectionResult, RunContext, register)

async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    # … do work, append Finding / Entity / Relationship …
    out.findings.append(Finding("my_source", "my_kind", {"...": "..."}, 0.85))
    return out

register(Module(key="my_mod", name="My Module",
                subject_types=["domain"], run=run,
                description="One-line summary."))
```

Then import it in `backend/app/modules/__init__.py` and (optionally) add
it to the `PLAN` map in `app/orchestrator.py`.

### Third-party plugins
Any installed Python package can expose a `base_osint.modules`
entry-point pointing at a module file that calls `register(...)` at
import time. `app/modules/plugins.py` walks the entry-point group on
startup.

### Add a source to the catalogue
Edit `backend/app/integrations/__init__.py` — pure declarative dict.
If you need a new API key, add it to `config.py` + `.env.example`.

### Rules (non-negotiable)
- Never fabricate. Missing key → `source_unavailable` finding.
- Rate-limit via `app.utils.ratelimit.gate(provider)` before outbound.
- SSRF-guard every user URL via `app.utils.ssrf.assert_public(url)`.
- Keep `data` flat — one top-level key per upstream payload.
- Record `source` + `confidence` on every relationship.

---

## 8 · Observability

- **Audit log**: `/api/audit` for every write action (admin only).
- **Metrics**: `/metrics` in Prometheus text — gauges for users /
  investigations / entities / findings / jobs (by status).
- **Module stats**: `/api/module_stats` — per-module total / done /
  error / running / queued + average runtime + success rate.
- **Analytics**: `/api/analytics?days=N` — daily histogram + top
  modules + top sources.
- **Live status**: `/api/progress/{inv}` for one investigation,
  `/api/ws/investigations/{inv}` for a push-style WebSocket snapshot.
- **Rate-limited?** Every response carries `x-base-duration-ms`.

---

## 9 · Exports

| Format | Endpoint | Shape |
| --- | --- | --- |
| JSON | `/api/reports/{id}.json` | full bundle (subjects + jobs + entities + rels + findings) |
| Markdown | `/api/reports/{id}.md` | analyst report |
| HTML | `/api/reports/{id}.html` | styled, dark theme |
| PDF | `/api/reports/{id}.pdf` | ReportLab, A4 |
| CSV | `/api/reports/{id}.csv` | findings only, 1 row each |
| STIX 2.1 | `/api/stix/{id}.stix.json` | bundle — importable by OpenCTI etc. |
| MISP v2 | `/api/misp/{id}.misp.json` | event w/ attributes |
| GraphML | `/api/exports/{id}.graphml` | Gephi / yEd / Maltego |
| GEXF | `/api/exports/{id}.gexf` | Gephi |
| GeoJSON | `/api/geojson/{id}.geojson` | map data |
| Mermaid | `/api/mermaid/{id}.mmd` | paste into markdown |
| ZIP | `/api/zip/{id}.zip` | every format in one archive |
| JSON backup | `/api/backup/{id}.base.json` | schema-versioned, restore-able |

---

## 10 · Interop

### STIX ingest
`POST /api/stix/{inv}/import` with a STIX 2.1 bundle — SDOs become
entities, SROs become relationships, de-duped by (type, value).

### TAXII 2.1 server
Every investigation is a TAXII collection, auto-exposed:
- `/api/taxii_server/discovery`
- `/api/taxii_server/api_root/collections/`
- `/api/taxii_server/api_root/collections/{inv_id}/objects/`

Point OpenCTI / MISP / your in-house TAXII client at that.

### OpenCTI push (outbound)
Run the `opencti_push` module on any investigation with
`OPENCTI_URL` + `OPENCTI_TOKEN` set — ships the STIX bundle.

### API keys for automation
`POST /api/apikeys` (one-time plaintext in response). The CLI and your
own scripts can use these in place of the Bearer JWT.

---

## 11 · Day-2 ops

| Thing | How |
| --- | --- |
| Rotate admin password | PATCH `/api/users/{id}` (admin) |
| Create analyst / viewer | POST `/api/auth/users` |
| Seal an investigation (freeze) | POST `/api/seal/{id}/seal` |
| Fork a sealed investigation | POST `/api/fork/{id}` |
| Share read-only (time-boxed) | POST `/api/share/{id}` → `/api/share/{token}` |
| Retention purge (90-day default) | POST `/api/retention` with `dry_run:false` |
| Back up everything | GET `/api/bulk_export.zip` |
| Restore one | POST `/api/backup/restore` with the JSON bundle |
| Health-ping every keyless source | POST `/api/sources/check` |
| Add a recurring run | POST `/api/schedules` (interval in seconds) |
| Define a plan preset | POST `/api/templates` → `/instantiate` |
| Combine investigations | POST `/api/combined_graph` with the id list |

---

## 12 · Testing

```bash
cd backend
DATABASE_URL="sqlite+aiosqlite:///./t.db" JWT_SECRET=t python -m pytest
```

65 tests pass on `main`. They're all offline — no test touches the
live internet. See `docs/testing.md`.

---

## 13 · When things go sideways

- **Jobs stay queued?** Compose running the worker service? `docker
  compose logs worker`. Dev mode (`uvicorn` alone) falls back to an
  in-process task — fine for <10-module plans.
- **All `source_unavailable`?** No API keys. The 45 keyless sources
  still produce real data; fill `.env` to light up the rest.
- **401 after sign-in?** `JWT_SECRET` changed. Clear browser
  `localStorage` and sign in again.
- **`relation "users" does not exist`** at startup? The bootstrap
  step didn't finish — check `docker compose logs backend`.
- **Rate-limited (429)?** You hit the API's per-IP budget. Wait 5s.
- **DNS modules all return nothing?** Your container's UDP/53 is
  blocked. The platform's fine; the network isn't.

---

## 14 · What's *not* in the box (and never will be from this side)

- No credential theft tooling, no exploitation primitives.
- No active scanning beyond bounded port probes w/ SSRF guards.
- No scraping of logged-in private services (LinkedIn, X post-API).
- Every module annotates its output with provenance — you get to
  decide what you do with it.

---

## 15 · Why the architecture looks the way it does

- **Module as the atom.** Everything funnels through a single
  async signature. New modules drop in without touching the
  orchestrator. Third-party plugins join via entry-points.
- **Finding, Entity, Relationship are separate.** You keep raw
  evidence (finding) next to the normalised graph nodes/edges, so you
  can always rebuild the graph from findings, and findings always
  carry provenance back to the source request.
- **Correlation runs after collection, not during.** Modules stay
  dumb; second-order relationships are a separate pass that reads
  everything persisted.
- **Everything is addressable via the API.** The UI is one consumer,
  the CLI is another, your own code can be a third via API keys.
- **Report is just a view of state.** The database is the source of
  truth; `.pdf`, `.stix.json`, `.graphml` are renders of the same
  bundle. You can delete reports and re-render.

That's the whole stack.
