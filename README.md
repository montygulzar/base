# base — OSINT investigation platform

Unified, modular, extensible OSINT collection + correlation + reporting
platform. **113 collection modules**, **~45 integration adapters**,
crypto subject-type extensions (BTC + ETH), Discord ID as a first-class
subject, one docker compose, a
Next.js dashboard with a module catalogue + ad-hoc scratchpad + global
search, a Python backend with investigation sharing / forking / tagging /
templates / schedules / audit / backup-restore, STIX / MISP / GraphML /
GEXF / GeoJSON / Mermaid / PDF / HTML / CSV / JSON / Markdown / ZIP
exports, a TAXII 2.1 server, a Prometheus `/metrics` endpoint, and a
headless CLI.

## Quick start

```bash
cp .env.example .env
docker compose up --build
```

- Frontend:  http://localhost:3000
- API docs:  http://localhost:8000/docs
- CLI:       `scripts/base_cli.py login admin@base.app admin`
- Metrics:   http://localhost:8000/metrics  (Prometheus text format)

Default admin: `admin@base.app / admin` — change it.

## Module catalogue — 100 modules

| Area | Modules |
| --- | --- |
| **Core infra** | `domain`, `ip`, `web`, `crawler`, `screenshot`, `security_txt`, `opengraph`, `csp`, `favicon`, `favicon_cluster`, `dns_auth`, `dnssec_axfr`, `caa`, `port_probe`, `url_liveness`, `url_unshorten` |
| **Passive DNS / CT** | `passive_dns` (7-source merge), `cert_pivot`, `certspotter`, `shodan_dns`, `wayback`, `robtex`, `reverse_ns`, `asn_prefixes`, `archive_whois` |
| **Threat intel** | `cti`, `abuse_ch`, `crowdsec`, `phishing_feeds`, `blocklists`, `dnsbl`, `spamhaus_dbl`, `virustotal`, `urlscan`, `greynoise`, `abuseipdb`, `intelx`, `pulsedive`, `mitre`, `osv`, `nvd_cpe`, `exploitdb` |
| **Exposure** | `internetdb`, `shodan`, `censys`, `fofa`, `zoomeye`, `honeypot`, `takeover`, `secrets_scan`, `risk`, `cloud_provider` |
| **Identity** | `username` (~50 sites), `github_user`, `github_dorks`, `bluesky`, `mastodon`, `reddit_user`, `hackernews`, `gravatar`, `email`, `emailrep`, `email_permute`, `hibp_pastes`, `pgp_keys`, `phone`, `company`, `opensanctions`, `ahmia` |
| **Media / docs** | `media`, `reverse_image`, `documents`, `metagoofil` |
| **Pivot / defence** | `typosquat`, `tld_twist`, `package_typosquat`, `bugbounty`, `tranco`, `webhook`, `opencti_push`, `taxii`, `ipapi`, `ip_api_com`, `s3_enum`, `cloud_bucket` |
| **Crypto** | `btc_addr`, `btc_tx` (mempool.space), `eth_addr` (Blockscout) |
| **Discord** | `discord_id` (snowflake → profile + creation date), `discord_invite` (server metadata, inviter, counts), `discord_mentions` (handle / id / invite harvester across all findings) |
| **Vulnerability feeds** | `cve_search`, `nvd_cpe`, `epss`, `kev`, `osv`, `exploitdb` |
| **Mail hygiene** | `smtp_banner`, `dns_auth`, `cert_expiry`, `tls_scan`, `caa` |
| **Defensive** | `url_canon`, `onion_validate`, `web_perf`, `homograph_gen`, `sitemap` |

Every module uses a shared `Module(key, name, subject_types, run)` contract
and persists `findings`, `entities`, and typed, provenanced `relationships`
through the orchestrator. Missing keys emit a `source_unavailable` finding
— **never fabricated data**.

## Subject types

`domain | ip | email | username | company | url | document | media | phone | btc | eth | discord`

## Correlation

Second-order edges computed over primary findings:

- `co_hosted_with` (shared IP)
- `same_asn_as`
- `same_mail_domain_as`
- `exposed_to` (CVEs mentioned in any finding → entity)
- `tagged_as` (malware family via MalwareBazaar)
- Honeypot / takeover / favicon-cluster signals
- Composite `risk` scorer (6 components, 0–100)

## API

OpenAPI is at `/docs`.

| Prefix | Purpose |
| --- | --- |
| `/api/auth`, `/api/users` | JWT auth, user CRUD, roles (admin / analyst / viewer) |
| `/api/investigations`    | investigations + subjects + jobs + findings + upload |
| `/api/modules`           | registered module list |
| `/api/integrations`      | source metadata + status |
| `/api/sources/check`     | one-shot health ping of 14 keyless feeds |
| `/api/graph`             | full graph + `/traverse?depth=N` bounded BFS |
| `/api/transforms`        | Maltego-style entity expansion |
| `/api/enrich`            | promote every discovered entity → new subject |
| `/api/timeline`          | ordered union of jobs + findings |
| `/api/stats`             | per-investigation + global histograms |
| `/api/search`            | full-text over findings |
| `/api/compare`           | entity-set diff between two investigations |
| `/api/ingest`            | bulk IOC paste → classified entities |
| `/api/templates`         | investigation templates (plan presets) |
| `/api/schedules`         | recurring runs (arq cron tick) |
| `/api/audit`             | admin audit log view |
| `/api/notes`             | analyst tags + notes on entities |
| `/api/reports`           | `.json .md .html .pdf .csv` |
| `/api/stix`              | STIX 2.1 export + ingest |
| `/api/misp`              | MISP v2 event export |
| `/api/exports`           | `.graphml .gexf` |
| `/api/taxii_server`      | TAXII 2.1 collections of all investigations |
| `/api/share`             | time-boxed read-only share tokens |
| `/api/progress`          | % done of the scheduled plan |
| `/api/screenshots`       | gallery + download |
| `/api/fork`              | deep-copy an investigation |
| `/api/jwt/decode`        | analyst helper: decode JWT header+payload |
| `/api/ws/investigations` | live job status over WebSocket |
| `/metrics`               | Prometheus text-exposition |

## Frontend

Next.js 14 + Tailwind + React Flow + dagre LR layout. Pages: dashboard
(stats + source health + ping), investigations (list / detail with
overview / findings / graph / jobs tabs, inline search, entity-type SVG
chart, screenshot gallery, expand-via-transforms button), integrations,
sources health, schedules, templates, reports, users, audit, login.

## Stack

- Backend: Python 3.11, FastAPI, SQLAlchemy 2.x async, Postgres
  (sqlite+aiosqlite for single-node dev), Redis + arq workers
- Frontend: Next.js 14 (App Router), TypeScript, Tailwind, React Flow +
  dagre
- Browser: Playwright / Chromium bundled in the backend image
- Infra: docker-compose (postgres, redis, backend, worker, frontend)

## Extending

Add a module:

```python
# backend/app/modules/my_module.py
from .base import (Module, Finding, Entity, Relationship,
                   CollectionResult, RunContext, register)

async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    # … do work, append Finding / Entity / Relationship …
    return out

register(Module(
    key="my_module",
    name="My module",
    subject_types=["domain"],
    description="",
    run=run,
))
```

Import it from `backend/app/modules/__init__.py`. External plugins
discovered via the `base_osint.modules` entry-point.

API keys go in `.env`; see `.env.example`. Any module that needs a
missing key emits a `source_unavailable` finding and skips gracefully.

## Licence

MIT. Draws architectural inspiration from SpiderFoot, Maltego, Recon-ng,
theHarvester, OSINT Framework, Sherlock, Amass, Photon, Metagoofil,
Shodan, Censys, VirusTotal, urlscan, Have I Been Pwned, OpenCTI, MISP.
Vendors nothing — every line of source is original.
