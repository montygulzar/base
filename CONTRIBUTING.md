# Contributing to base

Every module follows the same contract, which is what keeps 83 of them
manageable.

## Add a module

1. Create `backend/app/modules/<key>.py`.
2. Implement `async def run(subject: str, ctx: RunContext) -> CollectionResult`.
3. `register(Module(key=, name=, subject_types=[...], run=run, description=""))`.
4. Import it from `backend/app/modules/__init__.py`.
5. (Optional) Add it to the default `PLAN` in `backend/app/orchestrator.py`
   for the subject types it handles.

### Rules

- **Never fabricate data.** If a source needs a key and the key is
  missing, emit a `Finding(source, "source_unavailable", {"reason": "..."}, 0.0)`.
- **Rate-limit.** Use `await gate("provider")` from `app.utils.ratelimit`
  before outbound requests to a provider.
- **SSRF-guard.** User-supplied URLs go through `assert_public()` in
  `app.utils.ssrf`.
- **No blocking IO in the hot path.** Use `httpx.AsyncClient` /
  `dns.asyncresolver`. Wrap unavoidable blocking calls in
  `loop.run_in_executor`.
- **Keep the finding schema flat.** `source`, `kind`, `data` (dict),
  `confidence` ∈ [0, 1]. Put raw provider payloads under a single key,
  don't flatten them into the top-level.
- **Relationship evidence.** Always record `source` and `confidence`
  on relationships; use `evidence` for anything that would help a
  reviewer re-verify (query, ids, hashes).

## Add an integration

Integrations are declarative. Update
`backend/app/integrations/__init__.py` with:

```python
"my_source": {"configured": bool(s.MY_SOURCE_KEY),
              "scope": ["threat_intel"],
              "description": "...",
              "docs": "https://..."},
```

A matching env var goes in `backend/app/config.py` (default `""`) and
`.env.example`.

## Tests

Run `pytest` in `backend/`. Keep each new module's tests offline — don't
depend on live network from the suite. Unit-test pure functions
(regexes, parsers, scoring). Use the in-memory sqlite harness in
`tests/test_correlation.py` or `tests/test_stix.py` as a pattern for
DB-touching tests.

## Frontend

Pages live under `frontend/src/app/<route>/page.tsx`. Components under
`frontend/src/components/`. Use `useSWR(path, fetcher)` for reads and
`api(path, { method, body })` for writes.

## Commit message style

One line summary, imperative mood. Follow with a bulleted body if it
changes more than one thing. New modules and endpoints should be listed
explicitly in the body so git log diffing stays legible.

## Releasing

Push to `main`. CI-less for now — the quick-start docker compose is the
release artifact.
