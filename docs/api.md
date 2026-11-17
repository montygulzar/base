# API reference

The interactive OpenAPI docs live at `http://localhost:8000/docs`. This
file is a faster-to-scan catalogue.

Authentication is `Authorization: Bearer <JWT>` obtained from
`POST /api/auth/login` (form-encoded `username` + `password`). The
`/metrics`, `/api/share/{token}`, and `/api/taxii_server/*` endpoints
have their own rules below.

## Auth & users

| Method | Path | Notes |
| --- | --- | --- |
| POST | `/api/auth/login` | form-encoded, returns `access_token` |
| GET | `/api/auth/me` | current user |
| POST | `/api/auth/users` | admin only |
| GET | `/api/users` | admin only |
| PATCH | `/api/users/{id}` | admin only |
| DELETE | `/api/users/{id}` | admin only |

## Investigations

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/api/investigations` | list |
| POST | `/api/investigations` | create + optional subjects |
| GET | `/api/investigations/{id}` | one |
| DELETE | `/api/investigations/{id}` | admin only |
| GET | `/api/investigations/{id}/subjects` | |
| POST | `/api/investigations/{id}/subjects` | |
| POST | `/api/investigations/{id}/upload` | multipart file |
| POST | `/api/investigations/{id}/run` | optional `modules` list / `subject_ids` |
| GET | `/api/investigations/{id}/jobs` | |
| GET | `/api/investigations/{id}/findings` | `?module=&source=` filter |
| POST | `/api/jobs/{job_id}/retry` | |
| POST | `/api/jobs/{inv_id}/redrive_failed` | bulk retry failed jobs |
| POST | `/api/enrich/{inv_id}` | promote discovered entities to subjects |
| POST | `/api/triage` | autodetect + create + run in one call |
| POST | `/api/fork/{id}` | deep copy |
| GET  | `/api/progress/{id}` | % done + per-status counts |
| GET  | `/api/stats/{id}`, `/api/stats/global` | |

## Data model operations

| Method | Path | Notes |
| --- | --- | --- |
| POST | `/api/ingest/{id}` | bulk paste of IOCs → classified entities |
| POST | `/api/detect` | autodetect subject type |
| GET | `/api/search/{id}?q=` | full-text over findings |
| GET | `/api/compare/{a}/vs/{b}` | entity-set diff |
| GET | `/api/fuzzy?q=` | cross-investigation Levenshtein match |
| GET | `/api/timeline/{id}` | ordered jobs + findings |
| GET | `/api/recent?limit=` | newest N across all investigations |
| GET | `/api/audit` | admin only |
| POST | `/api/bulk/delete` / `/api/bulk/tag` | |
| POST | `/api/merge` | combine two entities |
| POST | `/api/notes/{entity_id}` | add tag + note |
| GET  | `/api/notes/{entity_id}` | list notes |
| DELETE | `/api/notes/{note_id}` | |
| GET  | `/api/inv_tags/{id}` / PUT `/api/inv_tags/{id}` | investigation labels |
| POST | `/api/retention` | admin purge |

## Graph

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/api/graph/{id}` | `?min_confidence=&type=` |
| GET | `/api/graph/{id}/traverse?type=&value=&depth=` | bounded BFS |
| GET | `/api/path/{id}?src=&dst=&max_depth=` | shortest path |
| POST | `/api/transforms/{id}/expand/{entity_id}` | Maltego-style expand |

## Exports

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/api/reports/{id}.{json,md,html,pdf,csv}` | |
| GET | `/api/stix/{id}.stix.json` | STIX 2.1 bundle |
| POST | `/api/stix/{id}/import` | ingest STIX bundle |
| GET | `/api/misp/{id}.misp.json` | MISP v2 event |
| GET | `/api/exports/{id}.{graphml,gexf}` | |
| GET | `/api/geojson/{id}.geojson` | points map |
| GET | `/api/zip/{id}.zip` | every format in one archive |
| GET | `/api/taxii_server/discovery` | TAXII 2.1, no auth |
| GET | `/api/taxii_server/api_root/collections/` | |
| GET | `/api/taxii_server/api_root/collections/{inv}/objects/` | |

## Schedules, templates, share

| Method | Path | Notes |
| --- | --- | --- |
| GET / POST | `/api/schedules` | |
| DELETE | `/api/schedules/{id}` | admin |
| POST | `/api/schedules/{id}/toggle` | |
| GET / POST | `/api/templates` | investigation plan presets |
| POST | `/api/templates/{id}/instantiate` | |
| POST | `/api/share/{id}` | mint read-only token |
| GET  | `/api/share/{token}` | no auth |

## Sources & health

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/api/integrations` | per-source status |
| POST | `/api/sources/check` | ping 14 keyless feeds |
| GET | `/api/module_stats` | per-module runtime stats |
| GET | `/api/version` | module count, DB counts |
| GET | `/metrics` | Prometheus text, no auth |
| WS | `/api/ws/investigations/{id}` | live job status |
| GET | `/api/screenshots/{id}` | list |
| GET | `/api/screenshots/{id}/{name}` | download |
| POST | `/api/jwt/decode` | analyst helper |
