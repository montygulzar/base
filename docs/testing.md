# Testing

## Suite layout

```
backend/tests/
  conftest.py                  # sets DATABASE_URL / JWT_SECRET for tests
  test_validators.py           # is_email / is_domain / is_ip / is_private_ip / is_username
  test_modules_registry.py     # every module registers + declares subject_types
  test_new_modules.py          # recent-additions coverage
  test_correlation.py          # co_hosted_with edges on an in-memory sqlite
  test_ssrf.py                 # SSRF guard matrix (localhost / private / link-local / scheme)
  test_misp_export.py          # MISP attribute shape
  test_stix.py                 # STIX bundle round-trip
  test_typosquat.py            # variant generation
  test_favicon.py              # mmh3 vectors
  test_phone.py                # phonenumbers happy / invalid
  test_dns_auth.py             # SPF / DMARC parsers
  test_secrets.py              # 6 credential-regex vectors
  test_csp.py                  # CSP parse + 4 weakness checks
  test_ingest.py               # IOC classifier
  test_permute.py              # email-format generator
  test_idn.py                  # homoglyph + script mix
  test_classify_helper.py      # extended classifier cases
  test_api_smoke.py            # route mount via _IncludedRouter walk
  test_api_integration.py      # TestClient: login → create → ingest → stats/compare
  test_api_integration2.py     # TestClient: templates / tags / graph filter / path / share
```

54 tests pass on the current `main`.

## Running

```bash
cd backend
DATABASE_URL="sqlite+aiosqlite:///./t.db" JWT_SECRET=t python -m pytest
```

All tests are offline — nothing hits the live internet. Modules that
depend on external services are either unit-tested on their pure-Python
helpers (regexes, parsers, scoring) or validated end-to-end against a
real uvicorn separately (see the commit log for live iana.org /
github.com / example.com runs).

## Writing a test

- Pure helper → import and assert.
- DB-touching → see `test_correlation.py` for the in-memory sqlite +
  `async_sessionmaker` pattern.
- API endpoint → see `test_api_integration2.py` for the TestClient
  pattern. Set `DATABASE_URL` + `JWT_SECRET` in the test module
  before importing the app so the session + engine pick up the override.

## What's NOT covered by tests

- Live outbound-HTTP modules (passive_dns, cert_pivot, …) — they're
  validated by live runs in the commit log but not in CI.
- WebSocket progress stream.
- Redis / arq worker loop (exercised by deployments, not by unit
  tests).

Those gaps are deliberate — keeping the suite deterministic and offline
beats flaky coverage of every provider.
