# Troubleshooting

### `source_unavailable` findings everywhere
You haven't set any API keys. That's expected — the free sources (crt.sh,
DNS, RDAP, bgpview, RIPEstat, SEC EDGAR, ThreatFox, NVD) still return real
data. Fill `.env` to light up the rest.

### HTTP 401 from the frontend after sign-in
`JWT_SECRET` changed between container restarts — clear the browser's
`localStorage` for `base_token` and sign in again.

### `relation "users" does not exist` at startup
The bootstrap step didn't run. Check `docker compose logs backend` — most
often Postgres wasn't ready yet; the healthcheck normally covers this.

### Jobs stay `queued`
The orchestrator currently uses an in-process background task (see
`BackgroundTasks` in `/api/investigations/{id}/run`). The arq worker is
plumbed for horizontal scaling but not yet enqueued from the API — fine
for single-node dev. To switch, change the `run` endpoint to
`await redis.enqueue_job("run_investigation", ...)`.

### `playwright: command not found` during tests
The test suite doesn't require playwright. Make sure the dev container
image was built from `backend/Dockerfile` (not pulled from elsewhere).
