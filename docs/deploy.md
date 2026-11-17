# Deploy

## Development

```bash
cp .env.example .env
docker compose up --build
```

- frontend: http://localhost:3000
- api docs: http://localhost:8000/docs
- default admin: `admin@base.local` / `admin` — change via the admin user endpoint before exposing anything.

The backend container runs `python -m app.bootstrap` on start, which creates
the schema and seeds the admin + integration-status rows.

## Production notes

- Set a long random `JWT_SECRET` (`openssl rand -hex 48`).
- Put the frontend and API behind a TLS-terminating reverse proxy.
- Restrict Postgres and Redis to the compose network (no ports mapped).
- Run `arq app.worker.WorkerSettings` with `--max-jobs` tuned for provider rate limits.
- Mount a durable volume for `/data/uploads`.
- Logs: all processes log to stdout; collect with your log stack.

## Scaling

- Workers are stateless; scale with `docker compose up --scale worker=N`.
- Postgres is the bottleneck for investigations with large entity sets; add read replicas if needed.
- Provider calls are bounded by `MAX_CONCURRENT_COLLECTORS`.
