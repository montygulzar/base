# base — OSINT investigation platform

Unified, modular, extensible OSINT collection + correlation + reporting
platform. **58 collection modules**, **~40 integration adapters**, one
docker compose, a Next.js dashboard, a Python backend with STIX / MISP /
GraphML / GEXF / PDF / HTML / CSV / JSON / Markdown exports and a
headless CLI.

## What's in the box

### 58 modules (as of this commit)

**Infrastructure**
`domain` (WHOIS / DNS / cert / headers / crt.sh), `ip` (RDAP / ASN /
BGPView / RIPEstat / reputation), `web` (HTTP probe + tech fingerprint
with 50+ signatures), `crawler` (Photon-style same-origin BFS),
`screenshot` (headless Playwright), `security_txt` (RFC 9116),
`opengraph`, `csp` (CSP header analyzer + 9 weakness checks), `favicon`
(Shodan / FOFA mmh3 hash), `favicon_cluster`, `dns_auth` (SPF / DMARC /
DKIM selector sweep), `dnssec_axfr`, `port_probe` (bounded, SSRF-guarded)

**Passive DNS / subdomain enumeration (Amass-level)**
`passive_dns` (merges hackertarget / rapiddns / anubis / OTX / subdomain.
center / bufferover / wayback), `cert_pivot` (crt.sh CN/SAN expansion),
`certspotter`, `shodan_dns`, `wayback`, `robtex`

**Threat intelligence**
`cti` (OTX + ThreatFox + NVD), `abuse_ch` (URLhaus + MalwareBazaar +
FeodoTracker), `crowdsec`, `phishing_feeds` (OpenPhish + PhishStats),
`blocklists` (Tor exits + Spamhaus DROP + ET compromised + Firehol L1),
`virustotal` (optional), `urlscan` (submit + poll), `greynoise`,
`abuseipdb`, `intelx`, `mitre` (ATT&CK T-ID mapping), `osv`

**Exposure / vulnerability**
`internetdb` (Shodan free per-IP), `shodan` (keyed), `censys` (keyed),
`fofa` (keyed), `zoomeye` (keyed), `honeypot` (classifier over existing
findings), `takeover` (subdomain-takeover check across 28 provider
patterns), `secrets_scan` (13 credential regex rules), `osv`, `risk`
(composite 0–100 score)

**Identity**
`username` (~50-site Sherlock-style check), `github_user` (profile +
repos + events + gists), `bluesky`, `mastodon`, `reddit_user`,
`gravatar`, `email` (syntax / MX / SPF / DMARC / HIBP), `emailrep`,
`email_permute` (format generator), `phone` (libphonenumber + Numverify
optional), `company` (SEC EDGAR + Companies House + OpenCorporates)

**Media / documents**
`media` (ExifTool + Pillow + imagehash + perceptual hash + GPS), `reverse_image`
(TinEye + Bing Visual + analyst deep-links), `documents` (PyMuPDF / python-docx /
openpyxl / indicator extraction), `metagoofil` (DuckDuckGo site: filetype:
+ inline metadata)

**Pivot / defence**
`typosquat` (dnstwist-style domain generation + DNS check),
`package_typosquat` (npm + PyPI name variants), `bugbounty` (ProjectDiscovery
Chaos scope lookup), `tranco`, `webhook` (Slack / Discord / JSON),
`opencti_push`, `taxii` (TAXII 2.1 pull)

### Correlation engine

Second-order edges computed from primary findings:
- `co_hosted_with` — domains sharing an IP
- `same_asn_as` — entities under one ASN
- `same_mail_domain_as` — emails at the same mail domain
- `exposed_to` — CVEs auto-extracted from any finding text
- (more from `honeypot`, `takeover`, `favicon_cluster`, `risk` modules)

### API surface

OpenAPI at `/docs`.

| Prefix | What it does |
| --- | --- |
| `/api/auth`           | JWT login / me / create user (admin) |
| `/api/users`          | user CRUD, roles (admin / analyst / viewer) |
| `/api/investigations` | investigation + subjects + jobs + findings |
| `/api/modules`        | list of registered modules |
| `/api/integrations`   | per-source configured / docs / last error |
| `/api/sources/check`  | live health ping across keyless endpoints |
| `/api/graph`          | full graph + `/traverse` (bounded BFS) |
| `/api/transforms`     | Maltego-style entity → new subject → run |
| `/api/enrich`         | promote every discovered entity to a subject |
| `/api/timeline`       | ordered union of jobs + findings |
| `/api/stats`          | per-investigation + global histograms |
| `/api/search`         | full-text over findings |
| `/api/compare`        | entity-set diff between two investigations |
| `/api/ingest`         | bulk IOC paste → classified entities |
| `/api/templates`      | investigation templates (plan presets) |
| `/api/schedules`      | recurring runs (arq cron tick) |
| `/api/audit`          | admin audit log view |
| `/api/notes`          | analyst tags + notes on entities |
| `/api/reports`        | `.json .md .html .pdf .csv` |
| `/api/stix`           | STIX 2.1 export + ingest |
| `/api/misp`           | MISP v2 event export |
| `/api/exports`        | `.graphml .gexf` |
| `/api/ws`             | live job status over WebSocket |

### Frontend (Next.js 14 + Tailwind + React Flow + dagre)

Pages: dashboard, investigations (list / detail with findings / graph /
jobs tabs + inline search), integrations, sources health, schedules,
templates, reports, users, audit, login.

### Headless CLI

`scripts/base_cli.py` — pure stdlib. Commands: `login`, `new`, `run`,
`findings`, `ingest`, `export`.

## Quick start

```bash
cp .env.example .env
docker compose up --build
```

- Frontend:  http://localhost:3000
- API docs:  http://localhost:8000/docs
- CLI:       `scripts/base_cli.py login admin@base.app admin`

Default admin is `admin@base.app / admin` — change it.

## Stack

- Backend: Python 3.11, FastAPI, SQLAlchemy 2.x async, Postgres (sqlite
  works for single-node dev), Redis + arq workers
- Frontend: Next.js 14 (App Router), TypeScript, Tailwind, React Flow +
  dagre LR layout
- Browser: Playwright / Chromium (preinstalled in the backend image for
  the `screenshot` module)
- Infra: docker-compose (5 services: postgres, redis, backend, worker,
  frontend)

## Extending

Add a module:

```python
# backend/app/modules/my_module.py
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register

async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    # ... do work, append Finding / Entity / Relationship ...
    return out

register(Module(
    key="my_module",
    name="My module",
    subject_types=["domain"],
    description="",
    run=run,
))
```

Then `from . import my_module` in `backend/app/modules/__init__.py`.
External plugins can install a `base_osint.modules` entry-point for
auto-discovery — see `backend/app/modules/plugins.py`.

Provider keys all go into `.env`; see `.env.example` for the full list.
Modules that need a key always emit a `source_unavailable` finding when
it's absent — never fabricated data.

## Licence

MIT. Draws architectural inspiration from SpiderFoot / Maltego / Recon-ng /
theHarvester / OSINT Framework / Sherlock / Amass / Photon / Metagoofil /
Shodan / Censys / VirusTotal / urlscan / HIBP / OpenCTI / MISP but
vendors nothing — all source is original.
